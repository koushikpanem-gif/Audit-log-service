"""ACCOUNT_DATA_ACCESS contract and account-access report tests."""

from __future__ import annotations

import sqlite3
import threading
from pathlib import Path
from typing import Any

import pytest
from conftest import ADMIN, AUDITOR, READER, WRITER, FakeClock, event_body, make_config
from starlette.testclient import TestClient

from audit_log_service.app import AuditApi, create_app
from audit_log_service.configuration import AuditConfiguration
from audit_log_service.verifier.bundle import Options, verify_bundle

REPORT = "/compliance/account-access-report"
WINDOW = {"from": "2024-01-01T00:00:00Z", "to": "2030-01-01T00:00:00Z"}


def api_of(client: TestClient) -> AuditApi:
    api: AuditApi = client.app.state.api  # type: ignore[attr-defined]
    return api


def payload(**overrides: object) -> dict[str, object]:
    body: dict[str, object] = {
        "dataCategory": "BALANCES",
        "accessType": "VIEW",
        "accessPurpose": "SERVICING",
        "channel": "INTERNAL_APP",
        "outcome": "GRANTED",
    }
    body.update(overrides)
    return body


def access(
    client: TestClient,
    actor: str = "alice",
    account: str = "acct-1",
    **overrides: object,
) -> dict[str, Any]:
    response = client.post(
        "/audit/events",
        json=event_body(
            eventType="ACCOUNT_DATA_ACCESS",
            actorId=actor,
            resourceType="CLIENT_ACCOUNT",
            resourceId=account,
            payload=payload(**overrides),
        ),
        headers=WRITER,
    )
    assert response.status_code == 201, response.text
    body: dict[str, Any] = response.json()
    return body


def report(client: TestClient, **params: str) -> Any:
    query = {"accountId": "acct-1", **WINDOW, **params}
    return client.get(REPORT, params=query, headers=AUDITOR)


def head_seq(client: TestClient) -> int:
    seq: int = client.get("/audit/verify", headers=AUDITOR).json()["headSeq"]
    return seq


def tamper(config: AuditConfiguration, *statements: str) -> None:
    connection = sqlite3.connect(config.db_path)
    for (name,) in connection.execute(
        "SELECT name FROM sqlite_master WHERE type = 'trigger'"
    ).fetchall():
        connection.execute(f"DROP TRIGGER {name}")
    for statement in statements:
        connection.execute(statement)
    connection.commit()
    connection.close()


def test_roles_are_enforced(client: TestClient) -> None:
    access(client)
    assert client.get(REPORT, params={"accountId": "a", **WINDOW}).status_code == 401
    for headers in (WRITER, READER):
        response = client.get(
            REPORT, params={"accountId": "a", **WINDOW}, headers=headers
        )
        assert response.status_code == 403
    assert report(client).status_code == 200
    admin = client.get(REPORT, params={"accountId": "acct-1", **WINDOW}, headers=ADMIN)
    assert admin.status_code == 200


@pytest.mark.parametrize(
    "params",
    [
        {"accountId": "a", "actorId": "b", **WINDOW},
        {**WINDOW},
        {"accountId": "a", "from": WINDOW["from"]},
        {"accountId": "a", "to": WINDOW["to"]},
        {"accountId": "a", "from": WINDOW["to"], "to": WINDOW["from"]},
        {"accountId": "a", "from": "yesterday", "to": WINDOW["to"]},
    ],
)
def test_parameters_are_validated(client: TestClient, params: dict[str, str]) -> None:
    access(client)
    before = head_seq(client)
    response = client.get(REPORT, params=params, headers=AUDITOR)
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "INVALID_INPUT"
    assert head_seq(client) == before


@pytest.mark.parametrize(
    "overrides",
    [
        {"dataCategory": "PASSWORDS"},
        {"accessType": "view"},
        {"accessPurpose": "CURIOSITY"},
        {"channel": "FAX"},
        {"outcome": "MAYBE"},
        {"accessPurpose": "OTHER"},
        {"accessPurpose": "OTHER", "justification": "   "},
        {"accessPurpose": "OTHER", "justification": "x" * 1001},
        {"outcome": "DENIED"},
        {"outcome": "DENIED", "denialReason": " "},
        {"outcome": "DENIED", "denialReason": "x" * 501},
        {"sessionId": "s" * 129},
        {"sourceIp": "1" * 65},
    ],
)
def test_event_payload_is_validated(
    client: TestClient, overrides: dict[str, object]
) -> None:
    response = client.post(
        "/audit/events",
        json=event_body(
            eventType="ACCOUNT_DATA_ACCESS",
            resourceType="CLIENT_ACCOUNT",
            payload=payload(**overrides),
        ),
        headers=WRITER,
    )
    assert response.status_code == 422
    assert "x" * 50 not in response.text


def test_event_requires_client_account_and_allows_extras(client: TestClient) -> None:
    wrong = client.post(
        "/audit/events",
        json=event_body(eventType="ACCOUNT_DATA_ACCESS", payload=payload()),
        headers=WRITER,
    )
    assert wrong.status_code == 422
    access(client, extra="allowed", sessionId="s-1", sourceIp="10.0.0.1")


def test_counts_groups_and_exceptions(client: TestClient) -> None:
    access(client)
    access(client)
    access(client, outcome="DENIED", denialReason="no entitlement")
    access(client, accessPurpose="OTHER", justification="audit follow-up")
    access(client, actor="bob", dataCategory="PROFILE", accessType="SEARCH")
    access(client, account="acct-2")
    client.post("/audit/events", json=event_body(resourceId="acct-1"), headers=WRITER)

    body = report(client).json()
    counts = body["counts"]
    assert counts["matchedEvents"] == 5
    assert counts["byActor"] == {"alice": 4, "bob": 1}
    assert counts["byOutcome"] == {"DENIED": 1, "GRANTED": 4}
    assert counts["byDataCategory"] == {"BALANCES": 4, "PROFILE": 1}
    assert counts["byAccessType"] == {"SEARCH": 1, "VIEW": 4}
    assert counts["byAccessPurpose"] == {"OTHER": 1, "SERVICING": 4}
    assert counts["unknownRedactedEvents"] == 0
    assert counts["exceptionRows"] == 2
    assert sum(group["count"] for group in body["groups"]) == 5
    assert body["groups"][0] == {
        "actorId": "alice",
        "dataCategory": "BALANCES",
        "accessPurpose": "OTHER",
        "outcome": "GRANTED",
        "accessType": "VIEW",
        "count": 1,
    }
    reasons = sorted(tuple(row["reasons"]) for row in body["exceptions"])
    assert reasons == [("DENIED",), ("PURPOSE_OTHER",)]
    assert body["scope"]["periodBasis"] == "recordedAt, inclusive UTC"
    assert len(body["exclusions"]) == 4
    assert body["recordCap"] == 10000
    assert "justification" not in str(body["exceptions"])


def test_actor_subject_spans_accounts(client: TestClient) -> None:
    access(client)
    access(client, account="acct-2")
    access(client, actor="bob")
    response = client.get(
        REPORT, params={"actorId": "alice", **WINDOW}, headers=AUDITOR
    )
    body = response.json()
    assert body["scope"]["subjectType"] == "ACTOR"
    assert body["counts"]["matchedEvents"] == 2


def test_period_is_inclusive_on_recorded_time(
    client: TestClient, clock: FakeClock
) -> None:
    first = access(client)
    clock.advance(seconds=10)
    second = access(client)
    body = report(
        client, **{"from": first["timestamp"], "to": first["timestamp"]}
    ).json()
    assert body["counts"]["matchedEvents"] == 1
    body = report(
        client, **{"from": first["timestamp"], "to": second["timestamp"]}
    ).json()
    assert body["counts"]["matchedEvents"] == 2


def test_separate_heads_meta_event_and_checkpoint(client: TestClient) -> None:
    last = access(client)
    access(client)
    body = report(client).json()
    verified, post = body["verifiedDataHead"], body["postReportHead"]
    assert verified["seq"] == 2
    assert post["seq"] == 3
    assert post["chainHash"] != verified["chainHash"]
    assert body["trustworthy"] is True
    assert body["trustLabel"].startswith("VERIFIED")
    assert body["integrity"]["intact"] is True
    assert last["seq"] == 1

    events = client.get("/audit/events", headers=READER).json()["items"]
    meta = [e for e in events if e["eventType"] == "COMPLIANCE_REPORT_GENERATED"]
    assert len(meta) == 1
    assert meta[0]["source"] == "system"
    assert meta[0]["eventId"] == post["reportEventId"]
    assert meta[0]["payload"]["verifiedDataHeadSeq"] == 2
    assert meta[0]["payload"]["recordCount"] == 2
    checkpoints = client.get("/audit/checkpoints", headers=AUDITOR).json()
    assert any(c["seq"] == 3 for c in checkpoints)
    assert client.get("/audit/verify", headers=AUDITOR).json()["intact"] is True


def test_evidence_verifies_offline_with_pinned_key(client: TestClient) -> None:
    access(client)
    body = report(client).json()
    key = client.get("/audit/public-key").json()["publicKey"]
    import json

    raw = json.dumps(body["evidence"]).encode()
    result = verify_bundle(raw, Options(pinned_key=key))
    assert result.status == "VERIFIED", result
    assert body["evidence"]["purpose"] == "COMPLIANCE_REPORT"
    assert body["evidence"]["bundleId"] == body["reportId"]
    assert body["evidence"]["completeness"]["throughSeq"] == 1


def test_redacted_grouping_leaves_are_unknown_not_assumed(client: TestClient) -> None:
    kept = access(client)
    redacted = access(client)
    response = client.post(
        "/audit/admin/redactions",
        json={
            "eventId": redacted["eventId"],
            "paths": ["/outcome", "/accessPurpose"],
            "reason": "privacy",
            "ticketId": "T-1",
        },
        headers=ADMIN,
    )
    assert response.status_code == 201
    body = report(client).json()
    counts = body["counts"]
    assert kept["seq"] == 1
    assert counts["matchedEvents"] == 2
    assert counts["unknownRedactedEvents"] == 1
    assert counts["byOutcome"] == {"GRANTED": 1, "UNKNOWN_REDACTED": 1}
    assert counts["byAccessPurpose"] == {"SERVICING": 1, "UNKNOWN_REDACTED": 1}
    row = body["exceptions"][0]
    assert row["reasons"] == ["UNKNOWN_GROUPING_FIELD"]
    assert row["outcome"] == "UNKNOWN_REDACTED"
    assert "DENIED" not in row["reasons"]
    assert body["integrity"]["redactedFields"] == 2
    assert body["trustworthy"] is True


def test_invalid_stored_grouping_value_is_unknown_invalid(
    client: TestClient, config: AuditConfiguration
) -> None:
    access(client)
    tamper(
        config,
        "UPDATE payload_leaves SET value = '\"BOGUS\"' WHERE pointer = '/outcome'",
    )
    body = report(client).json()
    assert body["counts"]["byOutcome"] == {"UNKNOWN_INVALID": 1}
    assert body["trustworthy"] is False


def test_archived_events_are_excluded(tmp_path: Path, clock: FakeClock) -> None:
    config = make_config(tmp_path, AUDIT_RETENTION_DAYS="1")
    client = TestClient(create_app(config, clock=clock), raise_server_exceptions=False)
    access(client)
    access(client)
    clock.advance(days=2)
    archived = client.post(
        "/audit/admin/archive", json={"dryRun": False}, headers=ADMIN
    )
    assert archived.status_code == 200, archived.text
    access(client)
    body = report(client).json()
    assert body["counts"]["matchedEvents"] == 1
    assert body["integrity"]["archivedRecords"] == 2
    assert body["trustworthy"] is True
    assert body["exclusions"][0].startswith("ARCHIVED")


def test_tampered_ledger_is_labelled_not_trustworthy(
    client: TestClient, config: AuditConfiguration
) -> None:
    access(client)
    access(client)
    tamper(config, f"UPDATE audit_events SET content_hash = '{'a' * 64}' WHERE seq = 1")
    body = report(client).json()
    assert body["trustworthy"] is False
    assert body["trustLabel"].startswith("NOT TRUSTWORTHY")
    assert body["integrity"]["intact"] is False
    assert body["integrity"]["totalViolationCount"] >= 1
    assert body["integrity"]["firstViolation"]["seq"] == 1
    assert body["verifiedDataHead"]["seq"] == 2
    assert body["postReportHead"]["seq"] == 3


def test_cap_rejects_without_partial_result_or_side_effects(
    client: TestClient,
) -> None:
    for _ in range(3):
        access(client)
    api_of(client).report_service._cap = 2  # noqa: SLF001
    before = head_seq(client)
    checkpoints = client.get("/audit/checkpoints", headers=AUDITOR).json()
    response = report(client)
    assert response.status_code == 422
    error = response.json()["error"]
    assert error["code"] == "REPORT_LIMIT_EXCEEDED"
    assert "narrow" in error["message"]
    assert error["details"] == [{"limit": "records", "value": 2}]
    assert head_seq(client) == before
    assert client.get("/audit/checkpoints", headers=AUDITOR).json() == checkpoints
    api_of(client).report_service._cap = 3  # noqa: SLF001
    assert report(client).status_code == 200


def test_byte_limit_is_a_distinct_unit(tmp_path: Path, clock: FakeClock) -> None:
    config = make_config(tmp_path, AUDIT_EXPORT_MAX_BYTES="2000")
    client = TestClient(create_app(config, clock=clock), raise_server_exceptions=False)
    access(client)
    access(client)
    response = report(client)
    assert response.status_code == 422
    assert response.json()["error"]["details"][0]["limit"] == "bytes"
    assert head_seq(client) == 2


def _barrier_report(client: TestClient, hook: str) -> tuple[Any, Any, dict[str, Any]]:
    reached, release = threading.Event(), threading.Event()
    service = api_of(client).report_service

    def pause() -> None:
        reached.set()
        assert release.wait(30)

    setattr(service, hook, pause)
    result: dict[str, Any] = {}

    def run_report() -> None:
        result["response"] = report(client)

    thread = threading.Thread(target=run_report)
    thread.start()
    assert reached.wait(30)
    return thread, release, result


@pytest.mark.parametrize("hook", ["after_verify", "after_select"])
def test_concurrent_append_waits_and_is_not_in_snapshot(
    client: TestClient, hook: str
) -> None:
    access(client)
    access(client)
    thread, release, result = _barrier_report(client, hook)
    outcome: dict[str, Any] = {}
    writer = threading.Thread(
        target=lambda: outcome.update(response=access(client, actor="late"))
    )
    writer.start()
    writer.join(timeout=1)
    assert writer.is_alive(), "the append must wait for the report transaction"
    release.set()
    thread.join(30)
    writer.join(30)

    body = result["response"].json()
    assert body["verifiedDataHead"]["seq"] == 2
    assert body["counts"]["matchedEvents"] == 2
    assert "late" not in body["counts"]["byActor"]
    assert outcome["response"]["seq"] == body["postReportHead"]["seq"] + 1


def test_concurrent_reports_are_serialized_and_consistent(client: TestClient) -> None:
    for _ in range(3):
        access(client)
    results: list[dict[str, Any]] = []
    lock = threading.Lock()

    def run_report() -> None:
        body = report(client).json()
        with lock:
            results.append(body)

    threads = [threading.Thread(target=run_report) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(60)
    assert len(results) == 4
    assert {r["counts"]["matchedEvents"] for r in results} == {3}
    assert sorted(r["postReportHead"]["seq"] for r in results) == [4, 5, 6, 7]
    assert len({r["reportId"] for r in results}) == 4
    assert client.get("/audit/verify", headers=AUDITOR).json()["intact"] is True


def test_openapi_documents_the_report(client: TestClient) -> None:
    paths = client.get("/openapi.json").json()["paths"]
    assert "get" in paths[REPORT]
    assert "501" not in paths[REPORT]["get"]["responses"]
