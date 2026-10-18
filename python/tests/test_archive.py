"""Archive state machine, crash stages, recovery and archive audit tests."""

from __future__ import annotations

import sqlite3
import uuid
from pathlib import Path
from typing import Any

import pytest
from conftest import ADMIN, AUDITOR, READER, WRITER, FakeClock, event_body, make_config
from starlette.testclient import TestClient

from audit_log_service import archive
from audit_log_service.app import AuditApi, create_app
from audit_log_service.configuration import AuditConfiguration
from audit_log_service.errors import ApiError
from audit_log_service.export_sets import SimulatedCrashError
from audit_log_service.verifier.bundle import Options, verify_bundle

ARCHIVE = "/audit/admin/archive"
DRY = {"dryRun": True}
RUN = {"dryRun": False}


def build(
    tmp_path: Path, clock: FakeClock, **env: str
) -> tuple[TestClient, AuditConfiguration]:
    config = make_config(tmp_path, AUDIT_RETENTION_DAYS="1", **env)
    app = create_app(config, clock=clock)
    return TestClient(app, raise_server_exceptions=False), config


def api_of(client: TestClient) -> AuditApi:
    api: AuditApi = client.app.state.api  # type: ignore[attr-defined]
    return api


def add(
    client: TestClient, count: int = 1, **overrides: object
) -> list[dict[str, Any]]:
    out = []
    for _ in range(count):
        response = client.post(
            "/audit/events", json=event_body(**overrides), headers=WRITER
        )
        assert response.status_code == 201
        out.append(response.json())
    return out


def run(client: TestClient, body: dict[str, Any] = RUN) -> Any:
    return client.post(ARCHIVE, json=body, headers=ADMIN)


def code(response: Any) -> str:
    value: str = response.json()["error"]["code"]
    return value


def archive_files(config: AuditConfiguration) -> list[Path]:
    if not config.archive_dir.is_dir():
        return []
    return sorted(config.archive_dir.iterdir())


def rows(config: AuditConfiguration, sql: str) -> list[tuple[Any, ...]]:
    connection = sqlite3.connect(config.db_path)
    try:
        return connection.execute(sql).fetchall()
    finally:
        connection.close()


def tamper(config: AuditConfiguration, *statements: str) -> None:
    connection = sqlite3.connect(config.db_path)
    connection.execute("PRAGMA ignore_check_constraints = ON")
    for (name,) in connection.execute(
        "SELECT name FROM sqlite_master WHERE type = 'trigger'"
    ).fetchall():
        connection.execute(f"DROP TRIGGER {name}")
    for statement in statements:
        connection.execute(statement)
    connection.commit()
    connection.close()


def audit(client: TestClient) -> dict[str, Any]:
    response = client.get("/audit/archive-audit", headers=AUDITOR)
    assert response.status_code == 200
    body: dict[str, Any] = response.json()
    return body


def jobs(client: TestClient) -> list[dict[str, Any]]:
    response = client.get("/audit/admin/archive-jobs", headers=ADMIN)
    assert response.status_code == 200
    items: list[dict[str, Any]] = response.json()["jobs"]
    return items


def test_dry_run_changes_nothing(tmp_path: Path, clock: FakeClock) -> None:
    client, config = build(tmp_path, clock)
    add(client, 3)
    clock.advance(days=2)
    response = run(client, DRY)
    assert response.status_code == 200
    body = response.json()
    assert (body["status"], body["count"], body["fromSeq"], body["toSeq"]) == (
        "DRY_RUN",
        3,
        1,
        3,
    )
    assert archive_files(config) == []
    assert rows(config, "SELECT COUNT(*) FROM archive_jobs") == [(0,)]
    assert rows(config, "SELECT COUNT(*) FROM audit_events WHERE archived = 1") == [
        (0,)
    ]
    assert rows(config, "SELECT COUNT(*) FROM audit_events") == [(3,)]


def test_nothing_to_archive_when_not_expired(tmp_path: Path, clock: FakeClock) -> None:
    client, config = build(tmp_path, clock)
    add(client, 2)
    assert run(client).json()["status"] == "NOTHING_TO_ARCHIVE"
    assert run(client, DRY).json()["status"] == "NOTHING_TO_ARCHIVE"
    assert archive_files(config) == []


def test_archive_publishes_signed_bundle_and_keeps_skeleton(
    tmp_path: Path, clock: FakeClock
) -> None:
    client, config = build(tmp_path, clock)
    events = add(client, 3)
    clock.advance(days=2)
    response = run(client)
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ARCHIVED"
    assert body["count"] == 3
    assert body["archiveEventSeq"] == 4

    files = archive_files(config)
    assert [f.name for f in files] == [body["archiveFile"]]
    key = client.get("/audit/public-key").json()["publicKey"]
    result = verify_bundle(files[0].read_bytes(), Options(pinned_key=key))
    assert result.status == "VERIFIED"
    assert result.record_count == 3

    # Skeleton hashes survive; business columns and leaves are gone.
    stored = rows(
        config,
        "SELECT seq, chain_hash, event_type, actor_id, payload_commitments, archived "
        "FROM audit_events WHERE seq <= 3 ORDER BY seq",
    )
    assert [r[1] for r in stored] == [e["chainHash"] for e in events]
    assert all(r[2] is None and r[3] is None and r[4] is None for r in stored)
    assert all(r[5] == 1 for r in stored)
    assert rows(config, "SELECT COUNT(*) FROM payload_leaves WHERE seq <= 3") == [(0,)]

    # Archived records are excluded and disclosed as such.
    assert client.get(f"/audit/events/{events[0]['eventId']}", headers=READER)
    assert (
        client.get(f"/audit/events/{events[0]['eventId']}", headers=READER).status_code
        == 404
    )
    listed = client.get("/audit/events", headers=READER).json()["items"]
    assert [e["eventType"] for e in listed] == ["RECORDS_ARCHIVED"]
    assert "archived" in body["note"].lower()

    report = client.get("/audit/verify", headers=AUDITOR).json()
    assert report["intact"] is True
    assert report["archivedRecords"] == 3
    summary = audit(client)
    assert summary["intact"] is True
    assert summary["archives"][0]["status"] == "OK"
    assert summary["coverage"]["complete"] is True

    job = jobs(client)[0]
    assert job["status"] == "COMMITTED"
    assert job["archiveEventSeq"] == body["archiveEventSeq"]
    assert job["archiveSha256"] == body["archiveSha256"]


def test_repeated_archives_are_cumulative_and_cover_old_authorizations(
    tmp_path: Path, clock: FakeClock
) -> None:
    client, config = build(tmp_path, clock, AUDIT_ARCHIVE_MAX_RECORDS="3")
    add(client, 7)
    clock.advance(days=2)
    first = run(client).json()
    assert (first["count"], first["moreAvailable"]) == (3, True)
    second = run(client).json()
    assert (second["fromSeq"], second["count"]) == (4, 3)
    third = run(client).json()
    assert (third["fromSeq"], third["count"], third["moreAvailable"]) == (7, 1, False)
    assert client.get("/audit/verify", headers=AUDITOR).json()["intact"] is True

    # Authorization events become eligible later and are archived as well.
    clock.advance(days=2)
    while (outcome := run(client).json())["status"] == "ARCHIVED":
        assert outcome["count"] <= 3
    report = client.get("/audit/verify", headers=AUDITOR).json()
    assert report["intact"] is True
    assert report["archivedRecords"] >= 9
    summary = audit(client)
    assert summary["intact"] is True
    assert summary["coverage"]["complete"] is True
    assert summary["archiveCount"] == len(archive_files(config))


def test_byte_limit_bounds_each_batch(tmp_path: Path, clock: FakeClock) -> None:
    client, _ = build(tmp_path, clock, AUDIT_ARCHIVE_MAX_BYTES="65536")
    big = {"payload": {"note": "x" * 20000}}
    add(client, 3, **big)
    clock.advance(days=2)
    first = run(client).json()
    assert (first["count"], first["moreAvailable"]) == (2, True)
    assert run(client).json()["count"] == 1
    assert client.get("/audit/verify", headers=AUDITOR).json()["intact"] is True


def test_single_oversized_record_is_rejected_without_change(
    tmp_path: Path, clock: FakeClock
) -> None:
    client, config = build(tmp_path, clock, AUDIT_ARCHIVE_MAX_BYTES="65536")
    add(client, 1, payload={"note": "x" * 60000})
    clock.advance(days=2)
    response = run(client)
    assert (response.status_code, code(response)) == (422, "ARCHIVE_RECORD_TOO_LARGE")
    assert archive_files(config) == []
    assert rows(config, "SELECT COUNT(*) FROM archive_jobs") == [(0,)]


def test_redaction_interaction(tmp_path: Path, clock: FakeClock) -> None:
    client, config = build(tmp_path, clock)
    first, second = add(client, 2)
    redacted = client.post(
        "/audit/admin/redactions",
        json={
            "eventId": first["eventId"],
            "paths": ["/note"],
            "reason": "request",
            "ticketId": "T-1",
        },
        headers=ADMIN,
    )
    assert redacted.status_code == 201
    clock.advance(days=2)
    assert run(client).json()["count"] == 3
    # An archived event can no longer be redacted.
    again = client.post(
        "/audit/admin/redactions",
        json={
            "eventId": second["eventId"],
            "paths": ["/amount"],
            "reason": "request",
            "ticketId": "T-2",
        },
        headers=ADMIN,
    )
    assert again.status_code == 409
    bundle = archive_files(config)[0].read_bytes()
    assert bundle.count(b"hello") == 1  # only the unredacted second event
    assert bundle.count(b"12.50") == 2
    assert client.get("/audit/verify", headers=AUDITOR).json()["intact"] is True
    assert audit(client)["intact"] is True


@pytest.mark.parametrize(
    "stage", [archive.AFTER_TEMP_FORCED, archive.AFTER_PUBLISH, archive.BEFORE_COMMIT]
)
def test_failed_publication_retains_plaintext_and_cleans_files(
    tmp_path: Path, clock: FakeClock, stage: str
) -> None:
    client, config = build(tmp_path, clock)
    add(client, 2)
    clock.advance(days=2)

    def fail(name: str) -> None:
        if name == stage:
            raise OSError("disk failure")

    api_of(client).archive.stage_hook = fail
    response = run(client)
    assert (response.status_code, code(response)) == (500, "ARCHIVE_PUBLICATION_FAILED")
    assert "plaintext was retained" in response.json()["error"]["message"]
    assert rows(config, "SELECT COUNT(*) FROM audit_events WHERE archived = 1") == [
        (0,)
    ]
    assert rows(config, "SELECT COUNT(*) FROM payload_leaves") == [(8,)]
    assert archive_files(config) == []
    job = jobs(client)[0]
    assert (job["status"], job["failureCode"], job["cleanupState"]) == (
        "FAILED",
        "PUBLICATION_FAILED",
        "DONE",
    )
    assert len(client.get("/audit/events", headers=READER).json()["items"]) == 2
    assert client.get("/audit/verify", headers=AUDITOR).json()["intact"] is True

    api_of(client).archive.stage_hook = None
    assert run(client).json()["status"] == "ARCHIVED"
    assert jobs(client)[0]["status"] == "COMMITTED"


@pytest.mark.parametrize(
    "stage",
    [
        archive.AFTER_JOB_RECORDED,
        archive.AFTER_TEMP_FORCED,
        archive.AFTER_PUBLISH,
        archive.BEFORE_COMMIT,
    ],
)
def test_crash_stages_recover_through_reconcile(
    tmp_path: Path, clock: FakeClock, stage: str
) -> None:
    client, config = build(tmp_path, clock)
    add(client, 2)
    clock.advance(days=2)

    def crash(name: str) -> None:
        if name == stage:
            raise SimulatedCrashError

    service = api_of(client).archive
    service.stage_hook = crash
    with pytest.raises(SimulatedCrashError):
        service.archive(False, "dev-admin")
    service.stage_hook = None

    # Plaintext is intact and the interrupted job blocks further archiving.
    assert rows(config, "SELECT COUNT(*) FROM audit_events WHERE archived = 1") == [
        (0,)
    ]
    assert rows(config, "SELECT COUNT(*) FROM payload_leaves") == [(8,)]
    assert jobs(client)[0]["status"] == "PREPARING"
    blocked = run(client)
    assert (blocked.status_code, code(blocked)) == (409, "ARCHIVE_JOB_INTERRUPTED")
    on_disk = archive_files(config)
    assert bool(on_disk) == (stage != archive.AFTER_JOB_RECORDED)

    reconciled = client.post("/audit/admin/archive-jobs/reconcile", headers=ADMIN)
    assert reconciled.status_code == 200
    job = reconciled.json()["jobs"][0]
    assert (job["status"], job["failureCode"], job["cleanupState"]) == (
        "FAILED",
        "INTERRUPTED",
        "DONE",
    )
    assert archive_files(config) == []
    assert run(client).json()["status"] == "ARCHIVED"
    assert client.get("/audit/verify", headers=AUDITOR).json()["intact"] is True


def test_restart_reconciles_interrupted_job(tmp_path: Path, clock: FakeClock) -> None:
    client, config = build(tmp_path, clock)
    add(client, 2)
    clock.advance(days=2)

    def crash(name: str) -> None:
        if name == archive.AFTER_PUBLISH:
            raise SimulatedCrashError

    service = api_of(client).archive
    service.stage_hook = crash
    with pytest.raises(SimulatedCrashError):
        service.archive(False, "dev-admin")
    assert len(archive_files(config)) == 1
    restarted = TestClient(create_app(config, clock=clock))
    assert archive_files(config) == []
    assert jobs(restarted)[0]["status"] == "FAILED"


def test_orphans_are_reported_but_never_deleted_and_committed_files_survive(
    tmp_path: Path, clock: FakeClock
) -> None:
    client, config = build(tmp_path, clock)
    add(client, 2)
    clock.advance(days=2)
    committed = run(client).json()["archiveFile"]
    orphan = config.archive_dir / f"archive-{uuid.uuid4()}.json"
    orphan.write_bytes(b"{}")
    (config.archive_dir / "notes.txt").write_text("operator file")
    status = client.post("/audit/admin/archive-jobs/reconcile", headers=ADMIN).json()
    assert status["orphanFiles"] == [orphan.name]
    assert status["unrecognizedFileCount"] == 1
    assert orphan.exists()
    assert (config.archive_dir / committed).exists()
    assert audit(client)["intact"] is True


def test_concurrent_run_is_rejected(tmp_path: Path, clock: FakeClock) -> None:
    client, _ = build(tmp_path, clock)
    add(client, 1)
    clock.advance(days=2)
    service = api_of(client).archive
    assert service._lock.acquire(blocking=False)
    try:
        response = run(client)
        assert (response.status_code, code(response)) == (409, "ARCHIVE_IN_PROGRESS")
        with pytest.raises(ApiError):
            service.reconcile()
    finally:
        service._lock.release()


def test_request_validation_and_roles(tmp_path: Path, clock: FakeClock) -> None:
    client, _ = build(tmp_path, clock)
    for body in ({}, {"dryRun": "yes"}, {"dryRun": True, "x": 1}, []):
        assert client.post(ARCHIVE, json=body, headers=ADMIN).status_code == 422
    assert client.post(ARCHIVE, json=DRY).status_code == 401
    assert client.post(ARCHIVE, json=DRY, headers=AUDITOR).status_code == 403
    assert client.get("/audit/admin/archive-jobs", headers=AUDITOR).status_code == 403
    assert client.get("/audit/archive-audit", headers=READER).status_code == 403
    assert client.get("/audit/archive-audit").status_code == 401


def archived_ledger(
    tmp_path: Path, clock: FakeClock
) -> tuple[TestClient, AuditConfiguration, dict[str, Any]]:
    client, config = build(tmp_path, clock)
    add(client, 2)
    clock.advance(days=2)
    return client, config, run(client).json()


def test_audit_reports_missing_file_distinctly(
    tmp_path: Path, clock: FakeClock
) -> None:
    client, config, body = archived_ledger(tmp_path, clock)
    (config.archive_dir / body["archiveFile"]).unlink()
    summary = audit(client)
    assert summary["intact"] is False
    assert summary["missingArchiveCount"] == 1
    assert summary["archives"][0]["status"] == "ARCHIVE_FILE_MISSING"
    # The chain itself is still intact: a missing archive is not a chain break.
    assert client.get("/audit/verify", headers=AUDITOR).json()["intact"] is True


def test_audit_detects_digest_and_content_tampering(
    tmp_path: Path, clock: FakeClock
) -> None:
    client, config, body = archived_ledger(tmp_path, clock)
    path = config.archive_dir / body["archiveFile"]
    original = path.read_bytes()
    path.write_bytes(original.replace(b"hello", b"jello"))
    assert audit(client)["archives"][0]["status"] == "DIGEST_MISMATCH"
    path.write_bytes(original)
    assert audit(client)["archives"][0]["status"] == "OK"


def test_audit_detects_skeleton_mismatch(tmp_path: Path, clock: FakeClock) -> None:
    client, config, _ = archived_ledger(tmp_path, clock)
    tamper(
        config,
        "UPDATE audit_events SET content_hash = '" + "0" * 64 + "' WHERE seq = 1",
    )
    summary = audit(client)
    assert summary["archives"][0]["status"] == "SKELETON_MISMATCH"
    assert client.get("/audit/verify", headers=AUDITOR).json()["intact"] is False


def test_audit_rejects_unsafe_file_name(tmp_path: Path, clock: FakeClock) -> None:
    client, config, body = archived_ledger(tmp_path, clock)
    tamper(
        config,
        "UPDATE archive_jobs SET final_name = '../escape.json'",
    )
    statuses = {a["status"] for a in audit(client)["archives"]}
    assert statuses <= {"FILE_NAME_UNSAFE", "METADATA_MISMATCH"}
    assert body["archiveFile"]
