"""Adversarial and cross-process validation over real HTTP and real SQLite files.

Every test is parametrized over the Java jar and the Python service, each started as
a separate OS process against its own synthetic database.
"""

from __future__ import annotations

import json
import shutil
import sqlite3
import subprocess
import sys
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from e2e_support import (
    ADMIN,
    AUDITOR,
    KINDS,
    LEDGER,
    PYTHON_DIR,
    READER,
    ServiceProcess,
    build_offline_ledger,
    java_available,
    raw_sql,
    run_verifier,
    violations,
)

pytestmark = pytest.mark.e2e


@pytest.fixture(params=KINDS)
def kind(request: pytest.FixtureRequest) -> str:
    if request.param == "java" and not java_available():
        pytest.skip("java or built jar not available")
    return str(request.param)


@pytest.fixture
def services():
    started: list[ServiceProcess] = []

    def factory(kind: str, home: Path, **env: str) -> ServiceProcess:
        service = ServiceProcess(kind, home, **env)
        started.append(service)
        return service

    yield factory
    for service in started:
        service.kill()


def test_scenarios_abc_over_http_with_offline_pinned_verification(
    kind: str, services, tmp_path: Path
) -> None:
    svc = services(
        kind,
        tmp_path / "home",
        AUDIT_EXPORT_CHUNK_MAX_RECORDS="2",
        AUDIT_EXPORT_SET_MAX_RECORDS="100",
    ).start()
    pinned = svc.public_key()

    # Scenario A: append, query, verify, checkpoint.
    first = svc.append(payload={"note": "secret", "amount": "12.50"})
    assert first["seq"] == 1
    for index in range(4):
        svc.append(resourceId=f"doc-{index}")
    page = svc.get("/audit/events?limit=2&order=asc", READER).json()
    assert [item["seq"] for item in page["items"]] == [1, 2]
    assert page["nextCursor"]
    assert svc.verify()["intact"] is True
    assert svc.post("/audit/admin/checkpoints", headers=ADMIN).status_code == 201
    assert svc.post("/audit/events", {"eventType": "X"}).status_code == 422
    assert svc.get("/audit/events", {"X-API-Key": "nope"}).status_code == 401

    # Scenario B: offline-verifiable bulk export.
    bundle = svc.get("/audit/export?actorId=alice")
    assert bundle.status_code == 200, bundle.text
    bundle_path = tmp_path / "bundle.json"
    bundle_path.write_text(bundle.text, encoding="utf-8")
    assert (
        run_verifier("--bundle", str(bundle_path), "--pinned-key", pinned).returncode
        == 0
    )
    wrong = run_verifier("--bundle", str(bundle_path), "--pinned-key", "A" * 43 + "=")
    assert wrong.returncode == 1
    assert (
        run_verifier("--bundle", str(bundle_path), "--allow-self-asserted").returncode
        == 0
    )
    unpinned = run_verifier("--bundle", str(bundle_path))
    assert unpinned.returncode == 1 and "TRUSTED_KEY_REQUIRED" in unpinned.stdout
    assert run_verifier("--bogus").returncode == 2

    # Redaction through the admin API.
    redaction = svc.post(
        "/audit/admin/redactions",
        {
            "eventId": first["eventId"],
            "paths": ["/note"],
            "reason": "r",
            "ticketId": "T-1",
        },
        ADMIN,
    )
    assert redaction.status_code == 201, redaction.text
    assert redaction.json()["cleanupStatus"] in {"COMPLETE", "PENDING"}
    redacted = svc.get(f"/audit/events/{first['eventId']}", READER).json()
    assert redacted["payload"]["note"] == "[REDACTED]"
    report = svc.verify()
    assert report["intact"] is True and report["redactedFields"] == 1

    # Export set with tiny chunks, verified offline from the downloaded files.
    created = svc.post("/audit/export-sets?actorId=alice", headers=AUDITOR)
    assert created.status_code == 202, created.text
    descriptor = created.json()
    for _ in range(120):
        descriptor = svc.get(f"/audit/export-sets/{descriptor['exportSetId']}").json()
        if descriptor["status"] != "RUNNING":
            break
        time.sleep(0.5)
    assert descriptor["status"] == "READY", descriptor
    assert descriptor["chunkCount"] >= 2
    manifest_dir = tmp_path / "set"
    manifest_dir.mkdir()
    manifest = svc.get(descriptor["manifestUrl"])
    (manifest_dir / "manifest.json").write_text(manifest.text, encoding="utf-8")
    for chunk in manifest.json()["chunks"]:
        content = svc.get(
            f"{descriptor['manifestUrl'].rsplit('/', 1)[0]}/chunks/{chunk['name']}"
        )
        assert content.status_code == 200
        (manifest_dir / chunk["name"]).write_bytes(content.content)
    result = run_verifier(
        "--manifest", str(manifest_dir / "manifest.json"), "--pinned-key", pinned
    )
    assert result.returncode == 0, result.stdout + result.stderr

    # Scenario C: access events and the signed report.
    for outcome, extra in (("GRANTED", {}), ("DENIED", {"denialReason": "no role"})):
        response = svc.post(
            "/audit/events",
            {
                "eventType": "ACCOUNT_DATA_ACCESS",
                "actorId": "bob",
                "resourceType": "CLIENT_ACCOUNT",
                "resourceId": "acct-1",
                "payload": {
                    "dataCategory": "BALANCES",
                    "accessType": "VIEW",
                    "accessPurpose": "SERVICING",
                    "channel": "API",
                    "outcome": outcome,
                    **extra,
                },
            },
        )
        assert response.status_code == 201, response.text
    now = time.gmtime()
    window = {
        "from": f"{now.tm_year - 1}-01-01T00:00:00Z",
        "to": f"{now.tm_year + 1}-01-01T00:00:00Z",
    }
    compliance = svc.get(
        "/compliance/account-access-report?accountId=acct-1&from="
        f"{window['from']}&to={window['to']}"
    )
    assert compliance.status_code == 200, compliance.text
    body = compliance.json()
    assert body["trustworthy"] is True
    assert (
        svc.get(
            "/compliance/account-access-report?accountId=acct-1&actorId=bob"
            f"&from={window['from']}&to={window['to']}"
        ).status_code
        == 422
    )


def test_archive_over_http_then_restart_keeps_ledger_intact(
    kind: str, services, tmp_path: Path
) -> None:
    home = tmp_path / "home"
    build_offline_ledger(home, 5, age_days=3)
    svc = services(kind, home, AUDIT_RETENTION_DAYS="1").start()
    pinned = svc.public_key()
    first = svc.get("/audit/events?limit=1&order=asc", READER).json()["items"][0]
    svc.append(resourceId="fresh")
    dry = svc.post("/audit/admin/archive", {"dryRun": True}, ADMIN)
    assert dry.status_code == 200 and dry.json().get("count") == 5, dry.text
    assert svc.verify()["archivedRecords"] == 0
    done = svc.post("/audit/admin/archive", {"dryRun": False}, ADMIN)
    assert done.status_code in {200, 201}, done.text
    assert done.json()["count"] == 5
    assert svc.get(f"/audit/events/{first['eventId']}", READER).status_code == 404
    live = svc.get("/audit/events?limit=50", READER).json()["items"]
    assert "fresh" in [item["resourceId"] for item in live]
    assert all(not item["resourceId"].startswith("doc-") for item in live)
    assert any(item["eventType"] == "RECORDS_ARCHIVED" for item in live)
    report = svc.verify()
    assert report["intact"] is True and report["archivedRecords"] == 5
    audit = svc.get("/audit/archive-audit")
    assert audit.status_code == 200, audit.text
    svc.restart()
    assert svc.public_key() == pinned
    assert svc.verify()["intact"] is True
    assert svc.append()["seq"] == 8
    again = svc.post("/audit/admin/archive", {"dryRun": False}, ADMIN).json()
    assert again["status"] == "NOTHING_TO_ARCHIVE"
    assert svc.verify()["intact"] is True


def test_multi_process_http_appends_are_contiguous(
    kind: str, services, tmp_path: Path
) -> None:
    svc = services(kind, tmp_path / "home", AUDIT_CHECKPOINT_INTERVAL="7").start()
    base = f"http://127.0.0.1:{svc.port}"
    workers = [
        subprocess.Popen(  # noqa: S603
            [sys.executable, "tests/e2e_http_worker.py", base, f"w{n}", "20"],
            cwd=PYTHON_DIR,
            stdout=subprocess.PIPE,
            text=True,
        )
        for n in range(4)
    ]
    seqs: list[int] = []
    for worker in workers:
        out, _ = worker.communicate(timeout=300)
        assert worker.returncode == 0, out
        seqs.extend(json.loads(out))
    assert sorted(seqs) == list(range(1, 81))
    report = svc.verify()
    assert report["intact"] is True and report["headSeq"] == 80
    assert len(svc.get("/audit/checkpoints").json()) >= 11


def test_two_server_processes_share_one_database(
    kind: str, services, tmp_path: Path
) -> None:
    first = services(kind, tmp_path / "home").start()
    second = services(kind, tmp_path / "home")
    second.port = 0
    second.start()
    assert first.public_key() == second.public_key()
    seqs: list[int] = []
    for index in range(10):
        for svc in (first, second):
            seqs.append(svc.append(resourceId=f"r{index}")["seq"])
    assert sorted(seqs) == list(range(1, 21))
    assert first.verify()["intact"] and second.verify()["intact"]
    assert second.verify()["headSeq"] == 20


def test_hard_kill_restart_preserves_chain_and_key(
    kind: str, services, tmp_path: Path
) -> None:
    svc = services(kind, tmp_path / "home").start()
    key = svc.public_key()
    for _ in range(3):
        svc.append()
    svc.post("/audit/admin/checkpoints", headers=ADMIN)
    svc.restart()
    assert svc.public_key() == key
    assert svc.append()["seq"] == 4
    report = svc.verify()
    assert report["intact"] is True and report["checkpointsVerified"] >= 1
    assert len(svc.get("/audit/checkpoints").json()) >= 1


def test_busy_wal_cleanup_returns_pending_then_recovers(
    kind: str, services, tmp_path: Path
) -> None:
    svc = services(
        kind,
        tmp_path / "home",
        AUDIT_CLEANUP_BUSY_TIMEOUT_MS="20",
        AUDIT_CLEANUP_MAX_ATTEMPTS="2",
    ).start()
    target = svc.append()
    svc.append()
    reader = sqlite3.connect(svc.db_path, isolation_level=None)
    reader.execute("BEGIN")
    reader.execute("SELECT count(*) FROM audit_events").fetchone()
    # A write after the snapshot starts forces the checkpoint to be blocked.
    svc.append()
    response = svc.post(
        "/audit/admin/redactions",
        {
            "eventId": target["eventId"],
            "paths": ["/note"],
            "reason": "r",
            "ticketId": "T",
        },
        ADMIN,
    )
    assert response.status_code == 201, response.text
    assert response.json()["cleanupStatus"] == "PENDING"
    status = svc.get("/audit/admin/redaction-cleanups", ADMIN).json()
    assert status["pendingJobs"] == 1
    reader.execute("ROLLBACK")
    reader.close()
    retried = svc.post("/audit/admin/redaction-cleanups/retry", headers=ADMIN).json()
    assert retried["pendingJobs"] == 0
    assert svc.verify()["intact"] is True


def test_rejected_writes_roll_back_and_leave_no_gap(
    kind: str, services, tmp_path: Path
) -> None:
    svc = services(kind, tmp_path / "home").start()
    svc.append()
    bad = [
        {
            "eventType": "RECORD_REDACTED",
            "actorId": "a",
            "resourceType": "R",
            "resourceId": "1",
            "payload": {},
        },
        {
            "eventType": "T",
            "actorId": "a",
            "resourceType": "R",
            "resourceId": "1",
            "payload": {},
            "source": "system",
        },
        {
            "eventType": "T",
            "actorId": "a",
            "resourceType": "R",
            "resourceId": "1",
            "payload": {},
            "timestamp": "2020-01-01T00:00:00Z",
        },
    ]
    for body in bad:
        assert svc.post("/audit/events", body).status_code in {403, 422}
    assert (
        svc.post(
            "/audit/admin/redactions",
            {"eventId": "missing", "paths": ["/x"], "reason": "r", "ticketId": "T"},
            ADMIN,
        ).status_code
        == 404
    )
    assert svc.append()["seq"] == 2
    assert svc.verify()["headSeq"] == 2


def test_report_is_one_consistent_snapshot_with_checkpoint(
    kind: str, services, tmp_path: Path
) -> None:
    svc = services(kind, tmp_path / "home").start()
    for outcome in ("GRANTED", "GRANTED"):
        svc.post(
            "/audit/events",
            {
                "eventType": "ACCOUNT_DATA_ACCESS",
                "actorId": "bob",
                "resourceType": "CLIENT_ACCOUNT",
                "resourceId": "acct-9",
                "payload": {
                    "dataCategory": "PROFILE",
                    "accessType": "VIEW",
                    "accessPurpose": "SERVICING",
                    "channel": "API",
                    "outcome": outcome,
                },
            },
        )
    url = (
        "/compliance/account-access-report?accountId=acct-9"
        "&from=2000-01-01T00:00:00Z&to=2999-01-01T00:00:00Z"
    )
    before = svc.verify()["headSeq"]
    body = svc.get(url).json()
    after = svc.verify()
    # The report appends exactly one system event and one checkpoint.
    assert after["headSeq"] == before + 1
    assert after["intact"] is True
    assert body["trustworthy"] is True


# --- Cross-process tamper matrix -------------------------------------------------

TEMPLATE_EVENTS = 6


CASES: dict[str, tuple[list[str], set[str]]] = {
    "content_edit": (
        ["UPDATE audit_events SET actor_id = 'mallory' WHERE seq = 3"],
        {"CONTENT_HASH_MISMATCH"},
    ),
    "chain_hash_edit": (
        ["UPDATE audit_events SET chain_hash = '" + "0" * 64 + "' WHERE seq = 4"],
        {"CHAIN_HASH_MISMATCH"},
    ),
    "prev_hash_edit": (
        ["UPDATE audit_events SET prev_hash = '" + "1" * 64 + "' WHERE seq = 3"],
        {"CHAIN_LINK_BROKEN"},
    ),
    "genesis": (
        ["UPDATE audit_events SET prev_hash = '" + "2" * 64 + "' WHERE seq = 1"],
        {"GENESIS_MISMATCH"},
    ),
    "gap": (
        [
            "DELETE FROM payload_leaves WHERE seq = 3",
            "DELETE FROM audit_events WHERE seq = 3",
        ],
        {"SEQUENCE_GAP"},
    ),
    "leaf_value": (
        [
            "UPDATE payload_leaves SET value = '\"forged\"' WHERE seq = 2 AND pointer = '/note'"
        ],
        {"PAYLOAD_VALUE_MISMATCH"},
    ),
    "unknown_version": (
        ["UPDATE audit_events SET hash_version = 99 WHERE seq = 2"],
        {"MALFORMED_RECORD"},
    ),
    "unauthorized_redaction": (
        ["DELETE FROM payload_leaves WHERE seq = 2 AND pointer = '/note'"],
        {"UNAUTHORIZED_REDACTION"},
    ),
    "unauthorized_archive": (
        [
            "DELETE FROM payload_leaves WHERE seq <= 2",
            "UPDATE audit_events SET event_type = NULL, actor_id = NULL, resource_type = NULL,"
            " resource_id = NULL, occurred_at = NULL, source = NULL,"
            " payload_commitments = NULL, archived = 1,"
            " archived_at = '2030-01-01T00:00:00.000000Z' WHERE seq <= 2",
        ],
        {"UNAUTHORIZED_ARCHIVE"},
    ),
    "checkpoint_signature": (
        ["UPDATE checkpoints SET signature = 'AAAA'"],
        {"CHECKPOINT_SIGNATURE_INVALID"},
    ),
    "tail_truncation": (
        [
            "DELETE FROM payload_leaves WHERE seq > 4",
            "DELETE FROM audit_events WHERE seq > 4",
        ],
        {"TRUNCATION_DETECTED"},
    ),
}


def _tamper_copy(template: Path, target: Path, statements: list[str]) -> None:
    shutil.copytree(template, target)
    raw_sql(target / "audit.db", *statements)


@pytest.fixture(scope="module")
def template(tmp_path_factory: pytest.TempPathFactory) -> Path:
    home = tmp_path_factory.mktemp("template")
    build_offline_ledger(home, TEMPLATE_EVENTS)
    return home


@pytest.mark.parametrize("case", sorted(CASES))
def test_tamper_matrix_detected_identically_by_both_services(
    case: str, services, template: Path, tmp_path: Path
) -> None:
    if not java_available():
        pytest.skip("java or built jar not available")
    statements, expected_types = CASES[case]
    results: dict[str, set[tuple[str, int | None]]] = {}
    for kind in KINDS:
        home = tmp_path / kind
        _tamper_copy(template, home, statements)
        svc = services(kind, home).start()
        report = svc.verify()
        assert report["intact"] is False, (kind, case, report)
        results[kind] = violations(report)
        found = {kind_ for kind_, _ in results[kind]}
        assert expected_types <= found, (kind, case, results[kind])
        svc.kill()
    assert results["java"] == results["python"], (case, results)


def test_untampered_template_is_intact_in_both_services(
    services, template: Path, tmp_path: Path
) -> None:
    if not java_available():
        pytest.skip("java or built jar not available")
    for kind in KINDS:
        home = tmp_path / kind
        shutil.copytree(template, home)
        svc = services(kind, home).start()
        report = svc.verify()
        assert report["intact"] is True, (kind, report)
        assert report["headSeq"] == TEMPLATE_EVENTS
        svc.kill()


def _iso(delta_days: float) -> str:
    moment = datetime.now(UTC) + timedelta(days=delta_days)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _system_event(service: Any, event_type: str, payload: dict[str, Any]) -> None:
    with service._store.write_transaction() as connection:  # noqa: SLF001
        service.append_system_event(
            connection, event_type, "admin", "AUDIT_EVENT", "target", payload
        )


def _redaction(target: dict[str, Any], **override: Any) -> dict[str, Any]:
    payload = {
        "targetSeq": target["seq"],
        "targetEventId": target["eventId"],
        "paths": ["/note"],
        "reason": "privacy request",
        "ticketId": "T-1",
        "requestedBy": "admin",
    }
    payload.update(override)
    return payload


def _archive(last: dict[str, Any], retention_days: int) -> dict[str, Any]:
    return {
        "archivedThroughSeq": last["seq"],
        "fromSeq": 1,
        "toSeq": last["seq"],
        "count": last["seq"],
        "cutoff": _iso(-8),
        "retentionDays": retention_days,
        "lastArchivedChainHash": last["chainHash"],
        "archiveFile": "archive-1.json",
        "archiveSha256": "f" * 64,
        "archiveBundleId": "bundle-1",
        "requestedBy": "admin",
    }


SKELETONIZE = [
    "DELETE FROM payload_leaves WHERE seq <= 2",
    "UPDATE audit_events SET event_type = NULL, actor_id = NULL, resource_type = NULL,"
    " resource_id = NULL, occurred_at = NULL, source = NULL,"
    " payload_commitments = NULL, archived = 1,"
    " archived_at = '2030-01-01T00:00:00.000000Z' WHERE seq <= 2",
]
DELETE_NOTE = "DELETE FROM payload_leaves WHERE seq = 1 AND pointer = '/note'"


def _forge(home: Path, scenario: str) -> set[tuple[str, int | None]] | None:
    """Forge authorization evidence the way an attacker with DB access would.

    Returns the exact expected violations, or None when the ledger must be intact.
    """
    _, service, events = build_offline_ledger(home, 3, checkpoint=False, age_days=10)
    if scenario == "valid_redaction_authorization":
        _system_event(service, "RECORD_REDACTED", _redaction(events[0]))
        raw_sql(home / "audit.db", DELETE_NOTE)
        return None
    if scenario == "malformed_redaction_authorization":
        _system_event(
            service, "RECORD_REDACTED", _redaction(events[0], targetEventId="wrong")
        )
        raw_sql(home / "audit.db", DELETE_NOTE)
        return {("UNAUTHORIZED_REDACTION", 1)}
    if scenario == "retention_policy_violation":
        service.advance_clock(9)  # type: ignore[attr-defined]
        _system_event(service, "RECORDS_ARCHIVED", _archive(events[1], 30))
        raw_sql(home / "audit.db", *SKELETONIZE)
        return {("RETENTION_POLICY_VIOLATION", 4)}
    if scenario == "valid_archive_authorization":
        service.advance_clock(9)  # type: ignore[attr-defined]
        _system_event(service, "RECORDS_ARCHIVED", _archive(events[1], 1))
        raw_sql(home / "audit.db", *SKELETONIZE)
        return None
    if scenario == "checkpoint_mismatch":
        signer = service._signer  # noqa: SLF001
        stamp = _iso(0)
        forged = signer.sign_checkpoint(
            ledger_id=LEDGER,
            seq=2,
            chain_hash=events[2]["chainHash"],
            created_at=stamp,
        )
        raw_sql(
            home / "audit.db",
            "INSERT INTO checkpoints(seq, chain_hash, created_at, key_id, signature)"
            f" VALUES (2, '{events[2]['chainHash']}', '{stamp}',"
            f" '{forged.key_id}', '{forged.signature}')",
        )
        return {("CHECKPOINT_MISMATCH", 2)}
    raise AssertionError(scenario)


FORGED = [
    "valid_redaction_authorization",
    "malformed_redaction_authorization",
    "retention_policy_violation",
    "valid_archive_authorization",
    "checkpoint_mismatch",
]


@pytest.mark.parametrize("scenario", FORGED)
def test_forged_authorization_evidence_is_judged_identically(
    scenario: str, services, tmp_path: Path
) -> None:
    if not java_available():
        pytest.skip("java or built jar not available")
    template = tmp_path / "template"
    expected = _forge(template, scenario)
    outcomes: dict[str, set[tuple[str, int | None]]] = {}
    for kind in KINDS:
        home = tmp_path / kind
        shutil.copytree(template, home)
        svc = services(kind, home, AUDIT_RETENTION_DAYS="1").start()
        report = svc.verify()
        outcomes[kind] = violations(report)
        if expected is None:
            assert report["intact"] is True, (kind, scenario, report["violations"])
        else:
            assert report["intact"] is False, (kind, scenario)
            assert expected <= outcomes[kind], (kind, scenario, outcomes[kind])
        svc.kill()
    assert outcomes["java"] == outcomes["python"], (scenario, outcomes)


def test_empty_ledger_is_intact_and_cannot_be_checkpointed(
    kind: str, services, tmp_path: Path
) -> None:
    svc = services(kind, tmp_path / "home").start()
    report = svc.verify()
    assert report["intact"] is True and report["headSeq"] == 0
    refused = svc.post("/audit/admin/checkpoints", headers=ADMIN)
    assert refused.status_code == 409
    assert refused.json()["error"]["code"] == "CONFLICT"
    assert svc.post("/audit/admin/checkpoints", headers=AUDITOR).status_code == 403
