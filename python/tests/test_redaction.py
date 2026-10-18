"""Redaction, cleanup queue and recovery tests against real SQLite."""

from __future__ import annotations

import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import pytest
from conftest import ADMIN, AUDITOR, READER, WRITER, FakeClock, event_body, make_config
from starlette.testclient import TestClient

from audit_log_service.app import AuditApi, create_app
from audit_log_service.configuration import AuditConfiguration

REDACT = "/audit/admin/redactions"


def make_client(config: AuditConfiguration, clock: FakeClock) -> TestClient:
    return TestClient(create_app(config, clock=clock), raise_server_exceptions=False)


def api_of(client: TestClient) -> AuditApi:
    api: AuditApi = client.app.state.api  # type: ignore[attr-defined]
    return api


def add(client: TestClient, **overrides: object) -> dict[str, Any]:
    response = client.post(
        "/audit/events", json=event_body(**overrides), headers=WRITER
    )
    assert response.status_code == 201
    body: dict[str, Any] = response.json()
    return body


def redact(
    client: TestClient, event_id: str, paths: list[str], **overrides: object
) -> Any:
    body: dict[str, object] = {
        "eventId": event_id,
        "paths": paths,
        "reason": "erasure request",
        "ticketId": "TCK-1",
    }
    body.update(overrides)
    return client.post(REDACT, json=body, headers=ADMIN)


def code(response: Any) -> str:
    value: str = response.json()["error"]["code"]
    return value


def leaf_count(config: AuditConfiguration, seq: int) -> int:
    connection = sqlite3.connect(config.db_path)
    try:
        return int(
            connection.execute(
                "SELECT COUNT(*) FROM payload_leaves WHERE seq = ?", (seq,)
            ).fetchone()[0]
        )
    finally:
        connection.close()


def test_redaction_removes_values_and_keeps_chain(
    client: TestClient, config: AuditConfiguration
) -> None:
    event = add(client)
    response = redact(client, event["eventId"], ["/note"])
    assert response.status_code == 201
    body = response.json()
    assert body["cleanupStatus"] == "COMPLETE"
    assert body["redactedPaths"] == ["/note"]
    assert body["targetSeq"] == event["seq"]
    assert "hello" not in response.text
    assert response.headers["location"] == f"/audit/events/{body['redactionEventId']}"
    assert leaf_count(config, event["seq"]) == 3

    view = client.get(f"/audit/events/{event['eventId']}", headers=READER).json()
    assert view["payload"]["note"] == "[REDACTED]"
    assert view["redactedPaths"] == ["/note"]
    assert view["chainHash"] == event["chainHash"]
    assert view["payloadCommitments"] == event["payloadCommitments"]

    report = client.get("/audit/verify", headers=AUDITOR).json()
    assert report["intact"] is True
    assert report["redactedFields"] == 1
    assert report["checkedRecords"] == 2


def test_redaction_of_system_event_stores_no_plaintext(
    client: TestClient, config: AuditConfiguration
) -> None:
    event = add(client)
    redact(client, event["eventId"], ["/note"])
    connection = sqlite3.connect(config.db_path)
    try:
        values = [r[0] for r in connection.execute("SELECT value FROM payload_leaves")]
    finally:
        connection.close()
    assert not any("hello" in value for value in values)


def test_subtree_root_and_duplicate_paths_are_expanded_and_deduplicated(
    client: TestClient, config: AuditConfiguration
) -> None:
    first = add(client)
    both = redact(client, first["eventId"], ["/tags", "/tags/0", "/tags/1"])
    assert both.status_code == 201
    assert both.json()["redactedPaths"] == ["/tags/0", "/tags/1"]

    second = add(client)
    root = redact(client, second["eventId"], [""])
    assert root.status_code == 201
    assert root.json()["redactedPaths"] == ["/amount", "/note", "/tags/0", "/tags/1"]
    assert leaf_count(config, second["seq"]) == 0
    assert client.get("/audit/verify", headers=AUDITOR).json()["intact"] is True


def test_conflicts_and_invalid_requests(client: TestClient) -> None:
    event = add(client)
    assert redact(client, "missing", ["/note"]).status_code == 404
    assert redact(client, event["eventId"], ["note"]).status_code == 422
    assert redact(client, event["eventId"], ["/nope"]).status_code == 422
    assert redact(client, event["eventId"], []).status_code == 422
    assert redact(client, event["eventId"], ["/note"], reason=" ").status_code == 422
    assert (
        redact(client, event["eventId"], ["/note"], reason="remove hello").status_code
        == 422
    )
    extra = client.post(
        REDACT,
        json={"eventId": "x", "paths": ["/a"], "reason": "r", "ticketId": "t", "x": 1},
        headers=ADMIN,
    )
    assert extra.status_code == 422

    first = redact(client, event["eventId"], ["/note"])
    assert first.status_code == 201
    again = redact(client, event["eventId"], ["/note"])
    assert again.status_code == 409
    system = redact(client, first.json()["redactionEventId"], [""])
    assert system.status_code == 409
    # Nothing was changed by the rejected requests.
    assert client.get("/audit/verify", headers=AUDITOR).json()["headSeq"] == 2


def test_redaction_requires_admin(client: TestClient) -> None:
    event = add(client)
    body = {
        "eventId": event["eventId"],
        "paths": ["/note"],
        "reason": "r",
        "ticketId": "t",
    }
    assert client.post(REDACT, json=body).status_code == 401
    assert client.post(REDACT, json=body, headers=READER).status_code == 403
    assert client.post(REDACT, json=body, headers=AUDITOR).status_code == 403


def test_failure_after_authorization_rolls_back_everything(
    client: TestClient,
    config: AuditConfiguration,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    event = add(client)

    def boom(*_: object, **__: object) -> int:
        raise RuntimeError("queue failure")

    monkeypatch.setattr(api_of(client).cleanup, "enqueue", boom)
    assert redact(client, event["eventId"], ["/note"]).status_code == 500
    assert leaf_count(config, event["seq"]) == 4
    report = client.get("/audit/verify", headers=AUDITOR).json()
    assert report["headSeq"] == 1
    assert report["intact"] is True


def test_held_reader_leaves_cleanup_pending_then_retry_completes(
    config: AuditConfiguration, clock: FakeClock, tmp_path: Path
) -> None:
    quick = make_config(
        tmp_path, AUDIT_CLEANUP_BUSY_TIMEOUT_MS="20", AUDIT_CLEANUP_MAX_ATTEMPTS="2"
    )
    client = make_client(quick, clock)
    event = add(client)
    reader = sqlite3.connect(quick.db_path)
    reader.execute("BEGIN")
    reader.execute("SELECT COUNT(*) FROM audit_events").fetchone()
    try:
        response = redact(client, event["eventId"], ["/note"])
        assert response.status_code == 201
        body = response.json()
        assert body["cleanupStatus"] == "PENDING"
        assert body["cleanupAttempts"] == 2
        # The committed deletion is not rolled back by a busy checkpoint.
        assert leaf_count(quick, event["seq"]) == 3
        status = client.get("/audit/admin/redaction-cleanups", headers=ADMIN).json()
        assert status["pendingJobs"] == 1
        assert status["jobs"][0]["lastOutcome"] == "BUSY"
        retry = client.post("/audit/admin/redaction-cleanups/retry", headers=ADMIN)
        assert retry.json()["pendingJobs"] == 1
    finally:
        reader.rollback()
        reader.close()
    retry = client.post("/audit/admin/redaction-cleanups/retry", headers=ADMIN)
    assert retry.status_code == 200
    assert retry.json()["pendingJobs"] == 0
    assert retry.json()["jobs"][0]["status"] == "COMPLETE"
    assert retry.json()["jobs"][0]["attempts"] >= 3


def test_restart_recovers_pending_cleanup(clock: FakeClock, tmp_path: Path) -> None:
    quick = make_config(
        tmp_path, AUDIT_CLEANUP_BUSY_TIMEOUT_MS="20", AUDIT_CLEANUP_MAX_ATTEMPTS="1"
    )
    client = make_client(quick, clock)
    event = add(client)
    reader = sqlite3.connect(quick.db_path)
    reader.execute("BEGIN")
    reader.execute("SELECT COUNT(*) FROM audit_events").fetchone()
    try:
        assert redact(client, event["eventId"], ["/note"]).json()["cleanupStatus"] == (
            "PENDING"
        )
    finally:
        reader.rollback()
        reader.close()
    restarted = make_client(quick, clock)
    status = restarted.get("/audit/admin/redaction-cleanups", headers=ADMIN).json()
    assert status["pendingJobs"] == 0
    assert status["completeJobs"] == 1


def test_concurrent_redactions_of_one_event_commit_once(
    config: AuditConfiguration, clock: FakeClock
) -> None:
    clients = [make_client(config, clock) for _ in range(4)]
    event = add(clients[0])
    with ThreadPoolExecutor(max_workers=4) as pool:
        statuses = list(
            pool.map(
                lambda c: redact(c, event["eventId"], ["/note"]).status_code, clients
            )
        )
    assert sorted(statuses) == [201, 409, 409, 409]
    report = clients[0].get("/audit/verify", headers=AUDITOR).json()
    assert report["intact"] is True
    assert report["headSeq"] == 2
