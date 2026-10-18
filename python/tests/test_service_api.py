from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest
from conftest import ADMIN, AUDITOR, READER, WRITER, FakeClock, event_body, make_config
from ledger_checks import assert_chain_valid
from starlette.testclient import TestClient

from audit_log_service.app import create_app
from audit_log_service.configuration import AuditConfiguration
from audit_log_service.signing import CheckpointSigner


def post(client: TestClient, body: object, headers: dict[str, str] = WRITER):  # type: ignore[no-untyped-def]
    return client.post("/audit/events", json=body, headers=headers)


def error_code(response) -> str:  # type: ignore[no-untyped-def]
    body = response.json()
    assert set(body) == {"error"}
    assert set(body["error"]) == {"code", "message", "details"}
    assert body["error"]["details"] == []
    return str(body["error"]["code"])


def test_append_returns_hashed_event_and_chain_is_independently_valid(
    client: TestClient, config: AuditConfiguration
) -> None:
    first = post(client, event_body())
    second = post(client, event_body(resourceId="doc-2"))

    assert first.status_code == 201
    assert first.headers["location"] == f"/audit/events/{first.json()['eventId']}"
    body = first.json()
    assert body["seq"] == 1
    assert body["source"] == "dev-writer"
    assert body["hashVersion"] == 1
    assert body["redactedPaths"] == []
    assert body["occurredAt"] is None
    assert body["timestamp"] == "2025-01-01T12:00:00.123456Z"
    assert body["payload"]["note"] == "hello"
    assert body["payloadCommitments"]["note"] != "hello"
    assert second.json()["prevHash"] == body["chainHash"]
    assert assert_chain_valid(config.db_path, config.ledger_id) == 2


@pytest.mark.parametrize(
    ("headers", "status"),
    [
        ({}, 401),
        ({"X-API-Key": "wrong"}, 401),
        ({"X-API-Key": " "}, 401),
        (READER, 403),
        (AUDITOR, 403),
    ],
)
def test_append_requires_writer_credentials(
    client: TestClient, headers: dict[str, str], status: int
) -> None:
    response = post(client, event_body(), headers)

    assert response.status_code == status
    assert error_code(response) in {"UNAUTHORIZED", "FORBIDDEN"}


def test_role_matrix(client: TestClient) -> None:
    event_id = post(client, event_body()).json()["eventId"]
    read_keys = {"dev-reader-only", "dev-auditor-only", "dev-admin-only"}
    routes = [
        ("get", "/audit/events", read_keys),
        ("get", f"/audit/events/{event_id}", read_keys),
        ("get", "/audit/checkpoints", {"dev-auditor-only", "dev-admin-only"}),
        ("post", "/audit/admin/checkpoints", {"dev-admin-only"}),
    ]
    keys = ["dev-writer-only", "dev-reader-only", "dev-auditor-only", "dev-admin-only"]
    for method, path, allowed in routes:
        for key in keys:
            response = client.request(method, path, headers={"X-API-Key": key})
            assert (response.status_code in {200, 201}) == (key in allowed), (
                method,
                path,
                key,
            )


def test_caller_cannot_supply_source_timestamp_or_reserved_values(
    client: TestClient,
) -> None:
    for extra in ({"source": "system"}, {"timestamp": "2025-01-01T00:00:00Z"}):
        response = post(client, event_body(**extra))
        assert response.status_code == 422
    for reserved in (
        "RECORD_REDACTED",
        "RECORDS_ARCHIVED",
        "BUNDLE_EXPORTED",
        "COMPLIANCE_REPORT_GENERATED",
    ):
        assert post(client, event_body(eventType=reserved)).status_code == 422


@pytest.mark.parametrize(
    "mutation",
    [
        {"eventType": ""},
        {"actorId": 5},
        {"payload": []},
        {"payload": "x"},
        {"occurredAt": "2025-01-01T00:00:00"},
        {"occurredAt": "yesterday"},
        {"occurredAt": 5},
        {"unexpected": 1},
    ],
)
def test_invalid_envelopes_are_rejected_without_echoing_values(
    client: TestClient, mutation: dict[str, object]
) -> None:
    response = post(client, event_body(**mutation))

    assert response.status_code == 422
    assert "stack" not in response.text.lower()


def test_missing_envelope_field_is_rejected(client: TestClient) -> None:
    body = event_body()
    del body["resourceId"]
    assert post(client, body).status_code == 422


def test_strict_json_and_media_type(client: TestClient) -> None:
    duplicate = b'{"eventType":"A","eventType":"B"}'
    response = client.post(
        "/audit/events",
        content=duplicate,
        headers={**WRITER, "Content-Type": "application/json"},
    )
    assert response.status_code == 422
    assert error_code(response) == "INVALID_JSON"

    nan = client.post(
        "/audit/events",
        content=b'{"payload":{"a":NaN}}',
        headers={**WRITER, "Content-Type": "application/json"},
    )
    assert nan.status_code == 422

    unsafe = client.post(
        "/audit/events",
        content=json.dumps(event_body(payload={"n": 9007199254740993})).encode(),
        headers={**WRITER, "Content-Type": "application/json"},
    )
    assert unsafe.status_code == 422

    text = client.post(
        "/audit/events", content=b"{}", headers={**WRITER, "Content-Type": "text/plain"}
    )
    assert text.status_code == 415


def test_request_and_payload_limits(tmp_path: Path, clock: FakeClock) -> None:
    config = make_config(
        tmp_path,
        AUDIT_REQUEST_LIMIT_BYTES="2048",
        AUDIT_PAYLOAD_LIMIT_BYTES="1024",
        AUDIT_MAX_DEPTH="3",
        AUDIT_MAX_LEAVES="4",
    )
    client = TestClient(create_app(config, clock=clock), raise_server_exceptions=False)

    huge = post(client, event_body(payload={"blob": "x" * 5000}))
    assert huge.status_code == 413
    assert error_code(huge) == "REQUEST_TOO_LARGE"

    big_payload = post(client, event_body(payload={"blob": "x" * 1500}))
    assert big_payload.status_code == 422

    deep = post(client, event_body(payload={"a": {"b": {"c": {"d": 1}}}}))
    assert deep.status_code == 422
    ok_depth = post(client, event_body(payload={"a": {"b": {"c": 1}}}))
    assert ok_depth.status_code == 201

    many = post(client, event_body(payload={"v": [1, 2, 3, 4, 5]}))
    assert many.status_code == 422
    assert post(client, event_body(payload={"v": [1, 2, 3, 4]})).status_code == 201


def test_empty_payload_and_scalar_commitments(client: TestClient) -> None:
    body = post(
        client,
        event_body(payload={"e": {}, "l": [], "n": None, "b": True, "f": 1.5}),
    ).json()

    assert body["payloadCommitments"]["e"] == {}
    assert body["payloadCommitments"]["l"] == []
    assert isinstance(body["payloadCommitments"]["n"], str)
    assert body["payload"] == {"e": {}, "l": [], "n": None, "b": True, "f": 1.5}


def test_recorded_timestamp_is_nondecreasing_when_clock_moves_back(
    client: TestClient, clock: FakeClock
) -> None:
    first = post(client, event_body()).json()
    clock.advance(seconds=-30)
    second = post(client, event_body()).json()
    clock.advance(seconds=40)
    third = post(client, event_body()).json()

    assert second["timestamp"] == first["timestamp"]
    assert third["timestamp"] > first["timestamp"]
    assert third["timestamp"] == "2025-01-01T12:00:10.123456Z"


def test_occurred_at_is_normalized_and_skew_limited(
    client: TestClient,
) -> None:
    ok = post(client, event_body(occurredAt="2025-01-01T13:00:00.5+01:00"))
    assert ok.json()["occurredAt"] == "2025-01-01T12:00:00.500000Z"
    assert (
        post(client, event_body(occurredAt="2025-01-01T12:05:00.123456Z")).status_code
        == 201
    )
    assert (
        post(client, event_body(occurredAt="2025-01-01T12:05:01Z")).status_code == 422
    )
    assert client.get("/audit/events", headers=READER).json()["items"][-1]["seq"] == 2


def test_account_access_contract_enforced(client: TestClient) -> None:
    payload = {
        "dataCategory": "BALANCES",
        "accessType": "VIEW",
        "accessPurpose": "SERVICING",
        "channel": "API",
        "outcome": "GRANTED",
        "extra": "allowed",
    }
    good = event_body(
        eventType="ACCOUNT_DATA_ACCESS", resourceType="CLIENT_ACCOUNT", payload=payload
    )
    assert post(client, good).status_code == 201
    wrong_resource = {**good, "resourceType": "DOCUMENT"}
    assert post(client, wrong_resource).status_code == 422
    other = {**good, "payload": {**payload, "accessPurpose": "OTHER"}}
    assert post(client, other).status_code == 422
    denied = {**good, "payload": {**payload, "outcome": "DENIED"}}
    assert post(client, denied).status_code == 422
    denied_ok = {
        **good,
        "payload": {**payload, "outcome": "DENIED", "denialReason": "no consent"},
    }
    assert post(client, denied_ok).status_code == 201
    bad_enum = {**good, "payload": {**payload, "channel": "FAX"}}
    assert post(client, bad_enum).status_code == 422


def test_get_event_and_not_found(client: TestClient) -> None:
    created = post(client, event_body()).json()

    fetched = client.get(f"/audit/events/{created['eventId']}", headers=READER)
    assert fetched.status_code == 200
    assert fetched.json() == created
    missing = client.get("/audit/events/nope", headers=READER)
    assert missing.status_code == 404
    assert error_code(missing) == "NOT_FOUND"


def test_archived_event_is_hidden_from_get_and_query(
    client: TestClient, config: AuditConfiguration
) -> None:
    import sqlite3

    created = post(client, event_body()).json()
    connection = sqlite3.connect(config.db_path)
    connection.execute("DELETE FROM payload_leaves WHERE seq = 1")
    connection.execute(
        "UPDATE audit_events SET archived = 1, archived_at = ?, event_type = NULL, "
        "actor_id = NULL, resource_type = NULL, resource_id = NULL, "
        "occurred_at = NULL, source = NULL, payload_commitments = NULL "
        "WHERE seq = 1",
        ("2025-01-02T00:00:00.000000Z",),
    )
    connection.commit()
    connection.close()

    assert (
        client.get(f"/audit/events/{created['eventId']}", headers=READER).status_code
        == 404
    )
    assert client.get("/audit/events", headers=READER).json()["items"] == []


def test_query_filters_and_ranges(client: TestClient, clock: FakeClock) -> None:
    post(client, event_body(actorId="alice"))
    clock.advance(minutes=1)
    post(client, event_body(actorId="bob", eventType="LOGIN", resourceId="doc-2"))
    clock.advance(minutes=1)
    post(client, event_body(actorId="alice", resourceType="TICKET"))

    def seqs(**params: str) -> list[int]:
        response = client.get("/audit/events", params=params, headers=READER)
        assert response.status_code == 200, response.text
        return [item["seq"] for item in response.json()["items"]]

    assert seqs() == [1, 2, 3]
    assert seqs(actorId="alice") == [1, 3]
    assert seqs(resourceType="TICKET") == [3]
    assert seqs(resourceId="doc-2") == [2]
    assert seqs(eventType="LOGIN") == [2]
    assert seqs(actorId="alice", resourceType="DOCUMENT") == [1]
    assert seqs(order="desc") == [3, 2, 1]
    assert seqs(**{"from": "2025-01-01T12:01:00.123456Z"}) == [2, 3]
    assert seqs(**{"to": "2025-01-01T12:01:00.123456Z"}) == [1, 2]
    assert seqs(
        **{"from": "2025-01-01T12:01:00.123456Z", "to": "2025-01-01T12:01:00.123456Z"}
    ) == [2]
    assert seqs(**{"from": "2025-01-01T13:01:00.123456+01:00"}) == [2, 3]


@pytest.mark.parametrize(
    "params",
    [
        {"from": "2025-01-02T00:00:00Z", "to": "2025-01-01T00:00:00Z"},
        {"from": "2025-01-01"},
        {"limit": "0"},
        {"limit": "501"},
        {"limit": "abc"},
        {"order": "sideways"},
        {"actorId": ""},
        {"cursor": "garbage"},
        {"cursor": "a.b"},
    ],
)
def test_invalid_query_parameters(client: TestClient, params: dict[str, str]) -> None:
    response = client.get("/audit/events", params=params, headers=READER)

    assert response.status_code == 422
    assert error_code(response) == "INVALID_INPUT"


def test_cursor_paging_uses_a_stable_snapshot(client: TestClient) -> None:
    for index in range(5):
        post(client, event_body(resourceId=f"doc-{index}"))

    first = client.get("/audit/events", params={"limit": 2}, headers=READER).json()
    assert [item["seq"] for item in first["items"]] == [1, 2]
    post(client, event_body())
    post(client, event_body())
    second = client.get(
        "/audit/events",
        params={"limit": 2, "cursor": first["nextCursor"]},
        headers=READER,
    ).json()
    third = client.get(
        "/audit/events",
        params={"limit": 2, "cursor": second["nextCursor"]},
        headers=READER,
    ).json()

    assert [item["seq"] for item in second["items"]] == [3, 4]
    assert [item["seq"] for item in third["items"]] == [5]
    assert third["nextCursor"] is None
    fresh = client.get("/audit/events", headers=READER).json()["items"]
    assert [item["seq"] for item in fresh] == [1, 2, 3, 4, 5, 6, 7]


def test_descending_paging(client: TestClient) -> None:
    for _ in range(4):
        post(client, event_body())
    page = client.get(
        "/audit/events", params={"limit": 3, "order": "desc"}, headers=READER
    ).json()
    rest = client.get(
        "/audit/events",
        params={"limit": 3, "order": "desc", "cursor": page["nextCursor"]},
        headers=READER,
    ).json()

    assert [item["seq"] for item in page["items"]] == [4, 3, 2]
    assert [item["seq"] for item in rest["items"]] == [1]


def test_cursor_is_bound_to_filters_order_and_key(
    client: TestClient, tmp_path: Path, clock: FakeClock
) -> None:
    for _ in range(3):
        post(client, event_body())
    cursor = client.get("/audit/events", params={"limit": 1}, headers=READER).json()[
        "nextCursor"
    ]

    for params in (
        {"limit": 1, "cursor": cursor, "actorId": "alice"},
        {"limit": 1, "cursor": cursor, "order": "desc"},
        {"limit": 1, "cursor": cursor + "A"},
        {"limit": 1, "cursor": cursor.replace(".", "x.", 1)},
    ):
        response = client.get("/audit/events", params=params, headers=READER)
        assert response.status_code == 422, params

    body, _, signature = cursor.partition(".")
    forged = json.loads(base64.urlsafe_b64decode(body + "=="))
    forged["lastSeq"] = 1
    forged["asOfSeq"] = 99
    token = (
        base64.urlsafe_b64encode(json.dumps(forged, separators=(",", ":")).encode())
        .rstrip(b"=")
        .decode()
        + "."
        + signature
    )
    assert (
        client.get(
            "/audit/events", params={"cursor": token}, headers=READER
        ).status_code
        == 422
    )


def test_checkpoints_every_interval_and_on_demand(
    tmp_path: Path, clock: FakeClock
) -> None:
    config = make_config(tmp_path, AUDIT_CHECKPOINT_INTERVAL="3")
    client = TestClient(create_app(config, clock=clock), raise_server_exceptions=False)

    empty = client.post("/audit/admin/checkpoints", headers=ADMIN)
    assert empty.status_code == 409
    assert error_code(empty) == "CONFLICT"
    for _ in range(7):
        post(client, event_body())
    listed = client.get("/audit/checkpoints", headers=AUDITOR).json()
    assert [item["seq"] for item in listed] == [6, 3]

    created = client.post("/audit/admin/checkpoints", headers=ADMIN)
    assert created.status_code == 201
    assert created.json()["seq"] == 7
    items = client.get(
        "/audit/checkpoints", params={"limit": 1}, headers=AUDITOR
    ).json()
    assert items == [created.json()]

    key = client.get("/audit/public-key").json()
    assert key["signatureAlgorithm"] == "Ed25519"
    head = client.get(
        "/audit/events", params={"order": "desc", "limit": 1}, headers=READER
    ).json()["items"][0]
    assert created.json()["chainHash"] == head["chainHash"]
    created_body = created.json()
    assert CheckpointSigner.verify_checkpoint(
        {
            "type": "audit-checkpoint/v1",
            "ledgerId": config.ledger_id,
            "seq": created_body["seq"],
            "chainHash": created_body["chainHash"],
            "createdAt": created_body["createdAt"],
            "keyId": created_body["keyId"],
            "signature": created_body["signature"],
        },
        key["publicKey"],
    )
    assert key["keyId"] == created.json()["keyId"]


def test_public_endpoints_need_no_credentials(client: TestClient) -> None:
    assert client.get("/health").status_code == 200
    assert client.get("/audit/public-key").status_code == 200
    spec = client.get("/openapi.json")
    assert spec.status_code == 200
    assert "/audit/events" in spec.json()["paths"]
    assert client.get("/docs").status_code == 200


@pytest.mark.parametrize(
    ("method", "path", "headers", "role_ok"),
    [
        ("get", "/compliance/account-access-report", AUDITOR, True),
    ],
)
def test_unbuilt_routes_never_fabricate_success(
    client: TestClient,
    method: str,
    path: str,
    headers: dict[str, str],
    role_ok: bool,
) -> None:
    assert client.request(method, path).status_code == 401
    assert client.request(method, path, headers=READER).status_code == 403
    response = client.request(method, path, headers=headers)

    assert response.status_code == 501
    assert error_code(response) == "NOT_IMPLEMENTED"


def test_event_mutation_methods_are_not_exposed(client: TestClient) -> None:
    event_id = post(client, event_body()).json()["eventId"]
    for method in ("put", "patch", "delete"):
        response = client.request(method, f"/audit/events/{event_id}", headers=ADMIN)
        assert response.status_code == 405
        assert error_code(response) == "METHOD_NOT_ALLOWED"
    assert client.get("/nope", headers=ADMIN).status_code == 404


def test_unexpected_failures_do_not_leak_details(
    client: TestClient, config: AuditConfiguration
) -> None:
    post(client, event_body())
    import sqlite3

    connection = sqlite3.connect(config.db_path)
    connection.execute("DROP TRIGGER payload_leaves_block_update")
    connection.execute("UPDATE payload_leaves SET value = '\"tampered\"' WHERE seq = 1")
    connection.commit()
    connection.close()

    response = client.get("/audit/events", headers=READER)

    assert response.status_code == 500
    assert error_code(response) == "INTERNAL_ERROR"
    assert "tampered" not in response.text


def test_api_keys_file_is_required_in_prod_and_used(
    tmp_path: Path, clock: FakeClock
) -> None:
    import hashlib

    key_file = tmp_path / "keys.json"
    key_file.write_text(
        json.dumps(
            {
                "svc": {
                    "keyHash": hashlib.sha256(b"custom-key").hexdigest(),
                    "roles": ["writer"],
                }
            }
        )
    )
    config = make_config(tmp_path, AUDIT_API_KEYS_FILE=str(key_file))
    client = TestClient(create_app(config, clock=clock), raise_server_exceptions=False)

    assert (
        client.post(
            "/audit/events", json=event_body(), headers={"X-API-Key": "dev-writer-only"}
        ).status_code
        == 401
    )
    response = client.post(
        "/audit/events", json=event_body(), headers={"X-API-Key": "custom-key"}
    )
    assert response.status_code == 201
    assert response.json()["source"] == "svc"
