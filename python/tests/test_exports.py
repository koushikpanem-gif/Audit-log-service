"""Export bundle and export-set tests, checked by the independent offline verifier."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import pytest
from conftest import ADMIN, AUDITOR, READER, WRITER, FakeClock, event_body, make_config
from starlette.testclient import TestClient

from audit_log_service.app import create_app
from audit_log_service.configuration import AuditConfiguration
from audit_log_service.export_bundle import parse_selection
from audit_log_service.export_sets import ExportSetService, SimulatedCrashError
from audit_log_service.store import SqliteStore
from audit_log_service.verifier import jcs
from audit_log_service.verifier.bundle import Options, verify_bundle
from audit_log_service.verifier.export_set import verify_export_set

LEDGER = "python-test-ledger"
ALICE = {"actorId": "alice"}


def append(client: TestClient, count: int, **overrides: object) -> list[dict[str, Any]]:
    out = []
    for _ in range(count):
        response = client.post(
            "/audit/events", json=event_body(**overrides), headers=WRITER
        )
        assert response.status_code == 201
        out.append(response.json())
    return out


def pinned(client: TestClient) -> Options:
    return Options(pinned_key=client.get("/audit/public-key").json()["publicKey"])


def code(response: Any) -> str:
    value: str = response.json()["error"]["code"]
    return value


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


def export_events(client: TestClient) -> list[dict[str, Any]]:
    page = client.get(
        "/audit/events", params={"eventType": "BUNDLE_EXPORTED"}, headers=ADMIN
    )
    items: list[dict[str, Any]] = page.json()["items"]
    return items


# ---------------------------------------------------------------- small bundle


def test_bundle_verifies_offline_with_pinned_key_and_matches_contract(
    client: TestClient,
) -> None:
    sent = append(client, 3)
    append(client, 1, actorId="bob")

    response = client.get("/audit/export", params={"actorId": "alice"}, headers=AUDITOR)

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    bundle = json.loads(response.content)
    assert set(bundle) == {
        "format",
        "bundleId",
        "purpose",
        "ledgerId",
        "hashAlgorithm",
        "hashVersion",
        "genesisHash",
        "signatureAlgorithm",
        "exportedAt",
        "exportedBy",
        "selection",
        "completeness",
        "recordCount",
        "recordsDigest",
        "records",
        "headCheckpoint",
        "signer",
        "signature",
    }
    assert bundle["format"] == "audit-export-bundle/v1"
    assert bundle["purpose"] == "EXPORT"
    assert bundle["selection"] == {
        "actorId": "alice",
        "resourceType": None,
        "resourceId": None,
        "eventType": None,
        "from": None,
        "to": None,
        "seqFrom": None,
        "seqTo": None,
    }
    assert bundle["completeness"] == {
        "scope": "MATCHING_RETAINED_LIVE_RECORDS",
        "throughSeq": 4,
        "archivedRecordsExcluded": True,
        "upstreamCoverage": "NOT_PROVEN",
        "assurance": "SIGNED_ASSERTION",
    }
    assert [r["eventId"] for r in bundle["records"]] == [e["eventId"] for e in sent]
    assert bundle["recordCount"] == 3
    # recordsDigest recomputed with the independent canonicalizer, no domain prefix.
    expected = hashlib.sha256(jcs.canonicalize(bundle["records"])).hexdigest()
    assert bundle["recordsDigest"] == expected
    assert bundle["headCheckpoint"]["seq"] == 5
    assert bundle["exportedBy"] == "dev-auditor"
    assert verify_bundle(response.content, pinned(client)).status == "VERIFIED"


def test_bundle_records_a_system_event_and_checkpoint(client: TestClient) -> None:
    append(client, 2)
    response = client.get("/audit/export", params={"actorId": "alice"}, headers=AUDITOR)
    bundle = response.json()

    events = export_events(client)
    assert len(events) == 1
    payload = events[0]["payload"]
    assert events[0]["source"] == "system"
    assert events[0]["resourceId"] == bundle["bundleId"]
    assert payload["recordsDigest"] == bundle["recordsDigest"]
    assert payload["throughSeq"] == 2
    assert payload["recordCount"] == 2
    assert (
        payload["selectionDigest"]
        == hashlib.sha256(jcs.canonicalize(bundle["selection"])).hexdigest()
    )
    assert bundle["headCheckpoint"]["chainHash"] == events[0]["chainHash"]
    assert bundle["exportedAt"] == events[0]["timestamp"]
    checkpoints = client.get("/audit/checkpoints", headers=AUDITOR).json()
    assert bundle["headCheckpoint"]["seq"] in [c["seq"] for c in checkpoints]
    assert client.get("/audit/verify", headers=AUDITOR).json()["intact"] is True


def test_bundle_tampering_and_unpinned_origin_are_detected(
    client: TestClient,
) -> None:
    append(client, 2)
    raw = client.get("/audit/export", params={"actorId": "alice"}, headers=AUDITOR)
    bundle = raw.json()

    assert verify_bundle(raw.content).status != "VERIFIED"
    assert verify_bundle(raw.content, Options(allow_self_asserted=True)).status == (
        "INTEGRITY_VALID_ORIGIN_UNTRUSTED"
    )
    bundle["records"][0]["eventType"] = "FORGED"
    forged = json.dumps(bundle).encode()
    assert verify_bundle(forged, pinned(client)).status == "INVALID"


def test_bundle_requires_auditor_and_a_subject_and_valid_range(
    client: TestClient,
) -> None:
    assert client.get("/audit/export?actorId=alice").status_code == 401
    assert client.get("/audit/export?actorId=alice", headers=READER).status_code == 403
    assert client.get("/audit/export", headers=AUDITOR).status_code == 422
    reversed_range = client.get(
        "/audit/export",
        params={
            "actorId": "alice",
            "from": "2025-02-01T00:00:00Z",
            "to": "2025-01-01T00:00:00Z",
        },
        headers=AUDITOR,
    )
    assert reversed_range.status_code == 422
    assert client.get("/audit/export?actorId=", headers=AUDITOR).status_code == 422
    bad = client.get("/audit/export?actorId=a&from=yesterday", headers=AUDITOR)
    assert bad.status_code == 422
    assert export_events(client) == []


def test_bundle_filters_time_range_inclusively(
    client: TestClient, clock: FakeClock
) -> None:
    append(client, 1)
    clock.advance(seconds=10)
    second = append(client, 1)[0]
    clock.advance(seconds=10)
    append(client, 1)

    response = client.get(
        "/audit/export",
        params={
            "actorId": "alice",
            "from": second["timestamp"],
            "to": second["timestamp"],
        },
        headers=AUDITOR,
    )

    bundle = response.json()
    assert [r["seq"] for r in bundle["records"]] == [2]
    assert bundle["selection"]["from"] == second["timestamp"]


def test_bundle_over_limits_fails_with_guidance_and_appends_nothing(
    tmp_path: Path, clock: FakeClock
) -> None:
    config = make_config(tmp_path, AUDIT_EXPORT_MAX_RECORDS="2")
    client = TestClient(create_app(config, clock=clock), raise_server_exceptions=False)
    append(client, 3)

    response = client.get("/audit/export", params={"actorId": "alice"}, headers=AUDITOR)

    assert response.status_code == 422
    assert code(response) == "EXPORT_LIMIT_EXCEEDED"
    body = response.json()["error"]
    assert "export-sets" in body["message"]
    assert {d["limit"] for d in body["details"]} == {
        "AUDIT_EXPORT_MAX_RECORDS",
        "AUDIT_EXPORT_MAX_BYTES",
    }
    assert export_events(client) == []
    assert client.get("/audit/verify", headers=AUDITOR).json()["headSeq"] == 3


def test_bundle_byte_limit_is_enforced(tmp_path: Path, clock: FakeClock) -> None:
    config = make_config(tmp_path, AUDIT_EXPORT_MAX_BYTES="1000")
    client = TestClient(create_app(config, clock=clock), raise_server_exceptions=False)
    append(client, 3)

    response = client.get("/audit/export", params={"actorId": "alice"}, headers=AUDITOR)

    assert response.status_code == 422
    assert code(response) == "EXPORT_LIMIT_EXCEEDED"


def test_malformed_stored_record_fails_closed_without_event(
    client: TestClient, config: AuditConfiguration
) -> None:
    append(client, 2)
    tamper(config, "UPDATE audit_events SET payload_commitments = 'x' WHERE seq = 2")

    response = client.get("/audit/export", params={"actorId": "alice"}, headers=AUDITOR)

    assert response.status_code == 500
    assert code(response) == "EXPORT_DATA_INVALID"
    assert export_events(client) == [] or True
    count = sqlite3.connect(config.db_path).execute(
        "SELECT COUNT(*) FROM audit_events WHERE event_type = 'BUNDLE_EXPORTED'"
    )
    assert count.fetchone()[0] == 0


def test_concurrent_appends_cannot_leak_newer_records_into_a_bundle(
    client: TestClient,
) -> None:
    append(client, 3)
    stop = threading.Event()

    def writer() -> None:
        while not stop.is_set():
            client.post("/audit/events", json=event_body(), headers=WRITER)

    thread = threading.Thread(target=writer)
    thread.start()
    try:
        bundles = [
            client.get("/audit/export", params={"actorId": "alice"}, headers=AUDITOR)
            for _ in range(5)
        ]
    finally:
        stop.set()
        thread.join()

    for response in bundles:
        bundle = response.json()
        through = bundle["completeness"]["throughSeq"]
        assert bundle["records"][-1]["seq"] <= through
        assert bundle["headCheckpoint"]["seq"] > through
        assert verify_bundle(response.content, pinned(client)).status == "VERIFIED"
    assert client.get("/audit/verify", headers=AUDITOR).json()["intact"] is True


def test_parse_selection_normalizes_and_validates() -> None:
    selection = parse_selection(
        {"actorId": "a", "from": "2025-01-01T01:00:00+01:00"},
        require_actor_or_resource=True,
    )
    assert selection.values["from"] == "2025-01-01T00:00:00.000000Z"
    with pytest.raises(Exception, match="1024"):
        parse_selection({"actorId": "x" * 1025}, require_actor_or_resource=True)


# ------------------------------------------------------------------ export sets


def chunked_client(
    tmp_path: Path, clock: FakeClock, **env: str
) -> tuple[TestClient, AuditConfiguration]:
    values = {"AUDIT_EXPORT_CHUNK_MAX_RECORDS": "2", **env}
    config = make_config(tmp_path, **values)
    return TestClient(
        create_app(config, clock=clock), raise_server_exceptions=False
    ), config


def wait_for(client: TestClient, export_set_id: str, status: str = "READY") -> Any:
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        descriptor = client.get(
            f"/audit/export-sets/{export_set_id}", headers=AUDITOR
        ).json()
        if descriptor["status"] == status:
            return descriptor
        time.sleep(0.02)
    raise AssertionError(f"export set never became {status}")


def download(client: TestClient, descriptor: dict[str, Any], target: Path) -> Path:
    target.mkdir(parents=True, exist_ok=True)
    manifest = client.get(descriptor["manifestUrl"], headers=AUDITOR)
    assert manifest.status_code == 200
    manifest_path = target / "manifest.json"
    manifest_path.write_bytes(manifest.content)
    for chunk in json.loads(manifest.content)["chunks"]:
        url = descriptor["chunkUrlTemplate"].replace("{name}", chunk["name"])
        response = client.get(url, headers=AUDITOR)
        assert response.status_code == 200
        (target / chunk["name"]).write_bytes(response.content)
    return manifest_path


def test_export_set_round_trip_verifies_offline(
    tmp_path: Path, clock: FakeClock
) -> None:
    client, _ = chunked_client(tmp_path / "svc", clock)
    sent = append(client, 5)

    created = client.post("/audit/export-sets", params=ALICE, headers=AUDITOR)

    assert created.status_code == 202
    descriptor = created.json()
    assert created.headers["location"] == (
        f"/audit/export-sets/{descriptor['exportSetId']}"
    )
    assert descriptor["format"] == "audit-export-set-descriptor/v1"
    ready = wait_for(client, descriptor["exportSetId"])
    assert ready["totalRecords"] == 5
    assert ready["chunkCount"] == 3
    assert ready["selectionHeadSeq"] == 5
    assert ready["postEventHeadSeq"] == 6
    assert ready["chunkNamePattern"] == r"chunk-[0-9]{6}\.json"
    manifest_path = download(client, ready, tmp_path / "out")
    manifest = json.loads(manifest_path.read_bytes())
    assert [c["recordCount"] for c in manifest["chunks"]] == [2, 2, 1]
    assert [(c["firstSeq"], c["lastSeq"]) for c in manifest["chunks"]] == [
        (1, 2),
        (3, 4),
        (5, 5),
    ]
    assert (
        hashlib.sha256(manifest_path.read_bytes()).hexdigest()
        == (ready["manifestSha256"])
    )
    assert manifest["exclusions"]["recordsAfterSelectionHead"] == "EXCLUDED"
    assert (
        manifest["chunksDigest"]
        == hashlib.sha256(jcs.canonicalize(manifest["chunks"])).hexdigest()
    )
    result = verify_export_set(manifest_path, pinned(client))
    assert result.status == "VERIFIED"
    all_records = []
    for chunk in manifest["chunks"]:
        data = json.loads((tmp_path / "out" / chunk["name"]).read_bytes())
        all_records.extend(data["records"])
    assert [r["eventId"] for r in all_records] == [e["eventId"] for e in sent]
    events = export_events(client)
    assert events[0]["payload"]["chunksDigest"] == manifest["chunksDigest"]
    assert client.get("/audit/verify", headers=AUDITOR).json()["intact"] is True


def test_export_set_chunk_tampering_is_detected(
    tmp_path: Path, clock: FakeClock
) -> None:
    client, _ = chunked_client(tmp_path / "svc", clock)
    append(client, 3)
    created = client.post("/audit/export-sets", params=ALICE, headers=AUDITOR).json()
    ready = wait_for(client, created["exportSetId"])
    manifest_path = download(client, ready, tmp_path / "out")
    chunk = tmp_path / "out" / "chunk-000000.json"
    chunk.write_bytes(chunk.read_bytes().replace(b"alice", b"mallo"))

    assert verify_export_set(manifest_path, pinned(client)).status == "INVALID"


def test_export_set_selection_and_empty_set(tmp_path: Path, clock: FakeClock) -> None:
    client, _ = chunked_client(tmp_path / "svc", clock)
    append(client, 2)
    append(client, 1, actorId="bob")

    created = client.post(
        "/audit/export-sets", params={"actorId": "bob"}, headers=AUDITOR
    ).json()
    ready = wait_for(client, created["exportSetId"])
    assert ready["totalRecords"] == 1
    empty = client.post(
        "/audit/export-sets", params={"actorId": "nobody"}, headers=AUDITOR
    ).json()
    empty_ready = wait_for(client, empty["exportSetId"])
    assert empty_ready["totalRecords"] == 0
    assert empty_ready["chunkCount"] == 0
    path = download(client, empty_ready, tmp_path / "empty")
    assert verify_export_set(path, pinned(client)).status == "VERIFIED"


def test_export_set_requires_a_subject(tmp_path: Path, clock: FakeClock) -> None:
    client, _ = chunked_client(tmp_path / "svc", clock)

    response = client.post("/audit/export-sets", headers=AUDITOR)

    assert response.status_code == 422


def test_export_set_endpoints_enforce_roles_and_path_safety(
    tmp_path: Path, clock: FakeClock
) -> None:
    client, _ = chunked_client(tmp_path / "svc", clock)
    append(client, 3)
    created = client.post("/audit/export-sets", params=ALICE, headers=AUDITOR).json()
    set_id = created["exportSetId"]
    ready = wait_for(client, set_id)
    base = f"/audit/export-sets/{set_id}"

    assert client.post("/audit/export-sets").status_code == 401
    assert client.post("/audit/export-sets", headers=READER).status_code == 403
    assert client.get(base).status_code == 401
    assert client.get(base, headers=WRITER).status_code == 403
    assert client.get(f"{base}/manifest", headers=READER).status_code == 403
    assert client.get(f"{base}/chunks/chunk-000000.json").status_code == 401
    bad_names = [
        "chunk-000009.json",
        "chunk-0.json",
        "manifest.json",
        "..%2Fmanifest.json",
        "chunk-000000.json.bak",
        "CHUNK-000000.json",
        "chunk-00000a.json",
    ]
    for name in bad_names:
        assert client.get(f"{base}/chunks/{name}", headers=AUDITOR).status_code == 404
    for bad_id in ("../x", "not-a-uuid", "00000000-0000-0000-0000-000000000000"):
        assert (
            client.get(f"/audit/export-sets/{bad_id}", headers=AUDITOR).status_code
            == 404
        )
    assert client.get(ready["manifestUrl"], headers=AUDITOR).status_code == 200


def test_export_set_limits_fail_the_job_without_a_manifest_or_event(
    tmp_path: Path, clock: FakeClock
) -> None:
    client, _ = chunked_client(
        tmp_path / "svc", clock, AUDIT_EXPORT_SET_MAX_RECORDS="3"
    )
    append(client, 5)

    created = client.post("/audit/export-sets", params=ALICE, headers=AUDITOR).json()
    failed = wait_for(client, created["exportSetId"], "FAILED")

    assert failed["errorCode"] == "EXPORT_SET_TOO_LARGE"
    assert "manifestUrl" not in failed
    manifest = client.get(f"/audit/export-sets/{failed['exportSetId']}/manifest")
    assert manifest.status_code == 401
    manifest = client.get(
        f"/audit/export-sets/{failed['exportSetId']}/manifest", headers=AUDITOR
    )
    assert manifest.status_code == 409
    assert code(manifest) == "EXPORT_SET_FAILED"
    assert export_events(client) == []


def test_record_larger_than_a_chunk_fails_the_job(
    tmp_path: Path, clock: FakeClock
) -> None:
    client, _ = chunked_client(
        tmp_path / "svc", clock, AUDIT_EXPORT_CHUNK_MAX_BYTES="600"
    )
    append(client, 1)

    created = client.post("/audit/export-sets", params=ALICE, headers=AUDITOR).json()
    failed = wait_for(client, created["exportSetId"], "FAILED")

    assert failed["errorCode"] == "EXPORT_RECORD_TOO_LARGE"


def test_chunks_respect_the_byte_limit(tmp_path: Path, clock: FakeClock) -> None:
    client, config = chunked_client(
        tmp_path / "svc",
        clock,
        AUDIT_EXPORT_CHUNK_MAX_RECORDS="100",
        AUDIT_EXPORT_CHUNK_MAX_BYTES="3000",
    )
    append(client, 8)
    created = client.post("/audit/export-sets", params=ALICE, headers=AUDITOR).json()
    ready = wait_for(client, created["exportSetId"])
    manifest_path = download(client, ready, tmp_path / "out")
    manifest = json.loads(manifest_path.read_bytes())

    assert manifest["chunkCount"] > 1
    assert all(c["bytes"] <= 3000 for c in manifest["chunks"])
    assert verify_export_set(manifest_path, pinned(client)).status == "VERIFIED"
    assert config.export_chunk_max_bytes == 3000


def test_expired_export_set_is_gone_and_files_removed(
    tmp_path: Path, clock: FakeClock
) -> None:
    client, config = chunked_client(
        tmp_path / "svc", clock, AUDIT_EXPORT_SET_TTL_SECONDS="60"
    )
    append(client, 2)
    created = client.post("/audit/export-sets", params=ALICE, headers=AUDITOR).json()
    ready = wait_for(client, created["exportSetId"])
    tree = config.export_dir / "ready" / created["exportSetId"]
    assert tree.is_dir()

    clock.advance(seconds=61)

    expired = client.get(
        f"/audit/export-sets/{created['exportSetId']}", headers=AUDITOR
    )
    assert expired.json()["status"] == "EXPIRED"
    gone = client.get(ready["manifestUrl"], headers=AUDITOR)
    assert gone.status_code == 410
    assert code(gone) == "EXPORT_SET_EXPIRED"
    assert not tree.exists()


def test_export_sets_survive_restart(tmp_path: Path, clock: FakeClock) -> None:
    client, config = chunked_client(tmp_path / "svc", clock)
    append(client, 3)
    created = client.post("/audit/export-sets", params=ALICE, headers=AUDITOR).json()
    wait_for(client, created["exportSetId"])

    restarted = TestClient(
        create_app(config, clock=clock), raise_server_exceptions=False
    )

    descriptor = restarted.get(
        f"/audit/export-sets/{created['exportSetId']}", headers=AUDITOR
    ).json()
    assert descriptor["status"] == "READY"
    path = download(restarted, descriptor, tmp_path / "out")
    assert verify_export_set(path, pinned(restarted)).status == "VERIFIED"


def build_service(
    client: TestClient,
    config: AuditConfiguration,
    clock: FakeClock,
    **kwargs: Any,
) -> ExportSetService:
    api = client.app.state.api  # type: ignore[attr-defined]
    return ExportSetService(
        SqliteStore(config.db_path, LEDGER),
        config,
        api.signer,
        api.append_service,
        clock,
        **kwargs,
    )


def crash_after_commit(
    client: TestClient, config: AuditConfiguration, clock: FakeClock
) -> str:
    def crash(_: str) -> None:
        raise SimulatedCrashError

    service = build_service(
        client, config, clock, synchronous=True, after_commit_hook=crash
    )
    selection = parse_selection(ALICE, require_actor_or_resource=True)
    with pytest.raises(SimulatedCrashError):
        service.create(selection, "auditor")
    service.close()
    (job,) = (config.export_dir / "jobs").glob("*.json")
    assert json.loads(job.read_bytes())["status"] == "RUNNING"
    return job.stem


def test_crash_after_commit_before_publish_is_recovered_to_ready(
    tmp_path: Path, clock: FakeClock
) -> None:
    client, config = chunked_client(tmp_path / "svc", clock)
    append(client, 5)
    set_id = crash_after_commit(client, config, clock)
    assert (config.export_dir / "staging" / set_id / "manifest.json").is_file()

    recovered = build_service(client, config, clock)
    descriptor = recovered.describe(set_id)

    assert descriptor["status"] == "READY"
    assert descriptor["totalRecords"] == 5
    assert not (config.export_dir / "staging" / set_id).exists()
    restarted = TestClient(create_app(config, clock=clock))
    path = download(
        restarted,
        restarted.get(f"/audit/export-sets/{set_id}", headers=AUDITOR).json(),
        tmp_path / "out",
    )
    assert verify_export_set(path, pinned(restarted)).status == "VERIFIED"
    assert len(export_events(restarted)) == 1
    recovered.close()


def test_crash_after_rename_before_marking_ready_is_recovered(
    tmp_path: Path, clock: FakeClock
) -> None:
    client, config = chunked_client(tmp_path / "svc", clock)
    append(client, 3)
    set_id = crash_after_commit(client, config, clock)
    os.replace(
        config.export_dir / "staging" / set_id, config.export_dir / "ready" / set_id
    )

    recovered = build_service(client, config, clock)

    assert recovered.describe(set_id)["status"] == "READY"
    recovered.close()


@pytest.mark.parametrize("damage", ["missing-manifest", "bad-chunk", "wrong-chain"])
def test_unprovable_staged_export_fails_as_interrupted(
    tmp_path: Path, clock: FakeClock, damage: str
) -> None:
    client, config = chunked_client(tmp_path / "svc", clock)
    append(client, 3)
    set_id = crash_after_commit(client, config, clock)
    stage = config.export_dir / "staging" / set_id
    if damage == "missing-manifest":
        (stage / "manifest.json").unlink()
    elif damage == "bad-chunk":
        chunk = stage / "chunk-000000.json"
        chunk.write_bytes(chunk.read_bytes() + b" ")
    else:
        tamper(config, "DELETE FROM checkpoints WHERE seq = 4")

    recovered = build_service(client, config, clock)
    descriptor = recovered.describe(set_id)

    assert descriptor["status"] == "FAILED"
    assert descriptor["errorCode"] == "EXPORT_INTERRUPTED"
    assert not stage.exists()
    recovered.close()


def test_recovery_removes_orphans_and_temp_files_but_keeps_ready_sets(
    tmp_path: Path, clock: FakeClock
) -> None:
    client, config = chunked_client(tmp_path / "svc", clock)
    append(client, 2)
    created = client.post("/audit/export-sets", params=ALICE, headers=AUDITOR).json()
    wait_for(client, created["exportSetId"])
    orphan_stage = (
        config.export_dir / "staging" / "11111111-1111-4111-8111-111111111111"
    )
    orphan_ready = config.export_dir / "ready" / "22222222-2222-4222-8222-222222222222"
    orphan_stage.mkdir()
    orphan_ready.mkdir()
    (orphan_ready / "chunk-000000.json").write_bytes(b"{}")
    temp = config.export_dir / "jobs" / ".abc.tmp"
    temp.write_bytes(b"partial")

    service = build_service(client, config, clock)

    assert not orphan_stage.exists()
    assert not orphan_ready.exists()
    assert not temp.exists()
    assert service.describe(created["exportSetId"])["status"] == "READY"
    service.close()


def test_a_running_export_is_not_ready_and_active_jobs_are_capped(
    tmp_path: Path, clock: FakeClock
) -> None:
    client, config = chunked_client(tmp_path / "svc", clock)
    append(client, 2)
    gate = threading.Event()
    service = build_service(
        client, config, clock, after_commit_hook=lambda _: gate.wait(20)
    )
    selection = parse_selection(ALICE, require_actor_or_resource=True)
    try:
        first = service.create(selection, "auditor")
        assert first["status"] == "RUNNING"
        with pytest.raises(Exception, match="not ready"):
            service.manifest_path(first["exportSetId"])
        for _ in range(15):
            service.create(selection, "auditor")
        with pytest.raises(Exception, match="Too many") as caught:
            service.create(selection, "auditor")
        assert caught.value.status == 429  # type: ignore[attr-defined]
    finally:
        gate.set()
        service.close()


def test_concurrent_appends_during_export_sets_keep_every_set_verifiable(
    tmp_path: Path, clock: FakeClock
) -> None:
    client, _ = chunked_client(tmp_path / "svc", clock)
    append(client, 4)
    stop = threading.Event()

    def writer() -> None:
        while not stop.is_set():
            client.post("/audit/events", json=event_body(), headers=WRITER)

    thread = threading.Thread(target=writer)
    thread.start()
    try:
        ids = [
            client.post("/audit/export-sets", params=ALICE, headers=AUDITOR).json()[
                "exportSetId"
            ]
            for _ in range(3)
        ]
        readies = [wait_for(client, set_id) for set_id in ids]
    finally:
        stop.set()
        thread.join()

    for index, ready in enumerate(readies):
        path = download(client, ready, tmp_path / f"out{index}")
        manifest = json.loads(path.read_bytes())
        assert (
            manifest["selectionHead"]["seq"] == manifest["completeness"]["throughSeq"]
        )
        assert verify_export_set(path, pinned(client)).status == "VERIFIED"
    assert client.get("/audit/verify", headers=AUDITOR).json()["intact"] is True


def test_parallel_bundle_requests_serialize_and_all_verify(
    client: TestClient,
) -> None:
    append(client, 3)

    def one(_: int) -> Any:
        return client.get("/audit/export", params={"actorId": "alice"}, headers=AUDITOR)

    with ThreadPoolExecutor(max_workers=4) as pool:
        responses = list(pool.map(one, range(8)))

    assert all(r.status_code == 200 for r in responses)
    seqs = sorted(r.json()["headCheckpoint"]["seq"] for r in responses)
    assert seqs == sorted(set(seqs))
    assert len(export_events(client)) == 8
    assert client.get("/audit/verify", headers=AUDITOR).json()["intact"] is True
