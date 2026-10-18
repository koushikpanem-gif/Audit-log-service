"""Full-ledger verifier tests: hand-computed vectors and raw-store attacks."""

from __future__ import annotations

import hashlib
import sqlite3
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from conftest import ADMIN, AUDITOR, READER, WRITER, FakeClock, event_body, make_config
from starlette.testclient import TestClient

from audit_log_service.configuration import AuditConfiguration
from audit_log_service.ledger_verifier import LedgerVerifier
from audit_log_service.store import SqliteStore

LEDGER = "python-test-ledger"


def independent_genesis(ledger_id: str) -> str:
    return hashlib.sha256(b"audit-log/genesis/v1\x00" + ledger_id.encode()).hexdigest()


def append(client: TestClient, count: int, **overrides: object) -> list[dict[str, Any]]:
    events = []
    for _ in range(count):
        response = client.post(
            "/audit/events", json=event_body(**overrides), headers=WRITER
        )
        assert response.status_code == 201
        events.append(response.json())
    return events


def verify(client: TestClient) -> dict[str, Any]:
    response = client.get("/audit/verify", headers=AUDITOR)
    assert response.status_code == 200
    report: dict[str, Any] = response.json()
    return report


def tamper(config: AuditConfiguration, *statements: str) -> None:
    """Act as a database administrator: drop guard triggers, then run raw SQL."""
    connection = sqlite3.connect(config.db_path)
    connection.execute("PRAGMA ignore_check_constraints = ON")
    triggers = connection.execute(
        "SELECT name FROM sqlite_master WHERE type = 'trigger'"
    ).fetchall()
    for (name,) in triggers:
        connection.execute(f"DROP TRIGGER {name}")
    for statement in statements:
        connection.execute(statement)
    connection.commit()
    connection.close()


def kinds(report: dict[str, Any]) -> set[tuple[str, int | None]]:
    return {(item["type"], item["seq"]) for item in report["violations"]}


def test_empty_ledger_is_intact_at_genesis(client: TestClient) -> None:
    report = verify(client)

    assert report["intact"] is True
    assert report["headSeq"] == 0
    assert report["headHash"] == independent_genesis(LEDGER)
    assert report["checkedRecords"] == 0
    assert report["firstViolation"] is None
    assert report["violations"] == []
    assert report["totalViolationCount"] == 0
    assert report["violationsTruncated"] is False
    assert report["hashAlgorithm"] == "SHA-256"
    assert report["ledgerId"] == LEDGER
    assert set(report) == {
        "intact",
        "ledgerId",
        "hashAlgorithm",
        "checkedRecords",
        "archivedRecords",
        "redactedFields",
        "headSeq",
        "headHash",
        "checkpointsVerified",
        "firstViolation",
        "violations",
        "totalViolationCount",
        "violationsTruncated",
        "verifiedAt",
        "durationMs",
    }


def test_intact_ledger_reports_head_and_verified_checkpoints(
    client: TestClient,
) -> None:
    events = append(client, 5)
    assert client.post("/audit/admin/checkpoints", headers=ADMIN).status_code == 201

    report = verify(client)

    assert report["intact"] is True
    assert report["checkedRecords"] == 5
    assert report["headSeq"] == 5
    assert report["headHash"] == events[-1]["chainHash"]
    assert report["checkpointsVerified"] == 1


def test_verify_requires_auditor_role(client: TestClient) -> None:
    assert client.get("/audit/verify").status_code == 401
    assert client.get("/audit/verify", headers=READER).status_code == 403
    assert client.get("/audit/verify", headers=WRITER).status_code == 403
    assert client.get("/audit/verify", headers=ADMIN).status_code == 200


def test_small_batches_give_the_same_result_as_one_batch(
    client: TestClient, config: AuditConfiguration
) -> None:
    append(client, 7)
    client.post("/audit/admin/checkpoints", headers=ADMIN)
    tamper(config, "UPDATE audit_events SET event_type = 'X' WHERE seq IN (2, 6)")
    api = client.app.state.api  # type: ignore[attr-defined]
    store = SqliteStore(config.db_path, LEDGER)

    def run(size: int) -> dict[str, Any]:
        report = LedgerVerifier(
            store, LEDGER, api.signer.public_key_base64, batch_size=size
        ).verify()
        report.pop("verifiedAt")
        report.pop("durationMs")
        return report

    assert run(1) == run(2) == run(3) == run(1000)
    assert run(2)["totalViolationCount"] == 2


TamperCase = tuple[str, list[str], set[tuple[str, int | None]]]

TAMPER_CASES: list[TamperCase] = [
    (
        "content",
        ["UPDATE audit_events SET event_type = 'CHANGED' WHERE seq = 3"],
        {("CONTENT_HASH_MISMATCH", 3)},
    ),
    (
        "chain-hash",
        ["UPDATE audit_events SET chain_hash = '" + "a" * 64 + "' WHERE seq = 3"],
        {("CHAIN_HASH_MISMATCH", 3), ("CHAIN_LINK_BROKEN", 4)},
    ),
    (
        "deleted-middle",
        [
            "DELETE FROM payload_leaves WHERE seq = 3",
            "DELETE FROM audit_events WHERE seq = 3",
        ],
        {("SEQUENCE_GAP", 4), ("CHAIN_LINK_BROKEN", 4)},
    ),
    (
        "genesis",
        ["UPDATE audit_events SET prev_hash = '" + "b" * 64 + "' WHERE seq = 1"],
        {("GENESIS_MISMATCH", 1), ("CHAIN_HASH_MISMATCH", 1)},
    ),
    (
        "leaf-value",
        [
            "UPDATE payload_leaves SET value = '\"forged\"' WHERE seq = 2 "
            "AND pointer = '/note'"
        ],
        {("PAYLOAD_VALUE_MISMATCH", 2)},
    ),
    (
        "leaf-removed",
        ["DELETE FROM payload_leaves WHERE seq = 2 AND pointer = '/note'"],
        {("UNAUTHORIZED_REDACTION", 2)},
    ),
    (
        "unknown-version",
        ["UPDATE audit_events SET hash_version = 2 WHERE seq = 2"],
        {("MALFORMED_RECORD", 2)},
    ),
    (
        "uppercase-hash",
        ["UPDATE audit_events SET content_hash = upper(content_hash) WHERE seq = 2"],
        {("MALFORMED_RECORD", 2)},
    ),
    (
        "bad-commitments",
        ["UPDATE audit_events SET payload_commitments = 'not json' WHERE seq = 2"],
        {("MALFORMED_RECORD", 2)},
    ),
    (
        "unauthorized-archive-flag",
        ["UPDATE audit_events SET archived = 1 WHERE seq = 2"],
        {("UNAUTHORIZED_ARCHIVE", 2), ("MALFORMED_RECORD", 2)},
    ),
    (
        "extra-leaf",
        [
            "INSERT INTO payload_leaves(seq, pointer, salt, value) "
            "VALUES (2, '/ghost', '" + "c" * 64 + "', '1')"
        ],
        {("MALFORMED_RECORD", 2)},
    ),
    (
        "bad-salt",
        ["UPDATE payload_leaves SET salt = 'zz' WHERE seq = 2 AND pointer = '/note'"],
        {("MALFORMED_RECORD", 2)},
    ),
    (
        "non-scalar-leaf",
        [
            "UPDATE payload_leaves SET value = '{\"a\":1}' WHERE seq = 2 "
            "AND pointer = '/note'"
        ],
        {("MALFORMED_RECORD", 2)},
    ),
    (
        "timestamp-backwards",
        [
            "UPDATE audit_events SET recorded_at = '2001-01-01T00:00:00.000000Z' "
            "WHERE seq = 3"
        ],
        {("MALFORMED_RECORD", 3), ("CONTENT_HASH_MISMATCH", 3)},
    ),
    (
        "invalid-utf8",
        ["UPDATE audit_events SET actor_id = CAST(x'ff41' AS TEXT) WHERE seq = 2"],
        {("MALFORMED_RECORD", 2)},
    ),
    (
        "null-hash",
        ["UPDATE audit_events SET chain_hash = '' WHERE seq = 2"],
        {("MALFORMED_RECORD", 2)},
    ),
    (
        "orphan-leaves",
        [
            "INSERT INTO payload_leaves(seq, pointer, salt, value) "
            "VALUES (99, '/x', '" + "d" * 64 + "', '1')"
        ],
        {("MALFORMED_RECORD", 99)},
    ),
    (
        "metadata",
        ["UPDATE ledger_meta SET ledger_id = 'someone-else'"],
        {("MALFORMED_RECORD", None)},
    ),
]


@pytest.mark.parametrize(
    ("statements", "expected"),
    [(case[1], case[2]) for case in TAMPER_CASES],
    ids=[case[0] for case in TAMPER_CASES],
)
def test_raw_store_tampering_is_localized(
    client: TestClient,
    config: AuditConfiguration,
    statements: list[str],
    expected: set[tuple[str, int | None]],
) -> None:
    append(client, 5)
    tamper(config, *statements)

    report = verify(client)

    assert report["intact"] is False
    assert expected <= kinds(report)
    assert report["totalViolationCount"] == len(report["violations"])
    first = report["firstViolation"]
    assert first == report["violations"][0]
    assert first["seq"] in {seq for _, seq in expected} | {None}


def test_tail_truncation_is_detected_through_signed_checkpoints(
    client: TestClient, config: AuditConfiguration
) -> None:
    append(client, 5)
    assert client.post("/audit/admin/checkpoints", headers=ADMIN).status_code == 201
    tamper(
        config,
        "DELETE FROM payload_leaves WHERE seq > 3",
        "DELETE FROM audit_events WHERE seq > 3",
    )

    report = verify(client)

    assert report["intact"] is False
    assert report["headSeq"] == 3
    assert ("TRUNCATION_DETECTED", 5) in kinds(report)


def test_tail_removal_with_checkpoints_removed_evades_detection(
    client: TestClient, config: AuditConfiguration
) -> None:
    # Documented limit: no surviving trusted checkpoint means no evidence of loss.
    append(client, 5)
    tamper(
        config,
        "DELETE FROM payload_leaves WHERE seq > 3",
        "DELETE FROM audit_events WHERE seq > 3",
    )

    report = verify(client)

    assert report["intact"] is True
    assert report["headSeq"] == 3


def test_checkpoint_forgery_and_mismatch_and_key_pinning(
    client: TestClient, config: AuditConfiguration
) -> None:
    events = append(client, 4)
    api = client.app.state.api  # type: ignore[attr-defined]
    signer = api.signer
    forged = signer.sign_checkpoint(
        ledger_id=LEDGER,
        seq=2,
        chain_hash=events[3]["chainHash"],
        created_at="2025-01-01T12:00:00.000000Z",
    )
    tamper(
        config,
        "INSERT INTO checkpoints(seq, chain_hash, created_at, key_id, signature) "
        f"VALUES (2, '{events[3]['chainHash']}', '2025-01-01T12:00:00.000000Z', "
        f"'{forged.key_id}', '{forged.signature}')",
        "INSERT INTO checkpoints(seq, chain_hash, created_at, key_id, signature) "
        f"VALUES (3, '{events[2]['chainHash']}', '2025-01-01T12:00:00.000000Z', "
        f"'{forged.key_id}', 'AAAA')",
    )

    report = verify(client)

    assert ("CHECKPOINT_MISMATCH", 2) in kinds(report)
    assert ("CHECKPOINT_SIGNATURE_INVALID", 3) in kinds(report)
    assert report["checkpointsVerified"] == 0

    other = make_config(
        Path(config.db_path).parent / "other-keys",
        AUDIT_DB_PATH=str(Path(config.db_path).parent / "other-keys" / "x.db"),
    )
    other_key = other.load_signer().public_key_base64
    store = SqliteStore(config.db_path, LEDGER)
    pinned_wrong = LedgerVerifier(store, LEDGER, other_key).verify()
    assert {"CHECKPOINT_SIGNATURE_INVALID"} <= {
        item["type"] for item in pinned_wrong["violations"]
    }


def test_diagnostics_are_capped_with_exact_totals_and_stable_order(
    client: TestClient, config: AuditConfiguration
) -> None:
    append(client, 150)
    tamper(config, "UPDATE audit_events SET event_type = 'FORGED'")

    report = verify(client)

    assert report["totalViolationCount"] == 150
    assert report["violationsTruncated"] is True
    assert [item["seq"] for item in report["violations"]] == list(range(1, 101))
    assert report["firstViolation"]["seq"] == 1
    assert report["checkedRecords"] == 150


def test_ties_are_ordered_by_violation_type_then_message(
    client: TestClient, config: AuditConfiguration
) -> None:
    append(client, 3)
    tamper(
        config,
        "UPDATE audit_events SET event_type = 'FORGED', "
        "chain_hash = '" + "e" * 64 + "' WHERE seq = 2",
    )

    types = [(item["seq"], item["type"]) for item in verify(client)["violations"]]

    assert types == sorted(
        types,
        key=lambda pair: (
            pair[0],
            [
                "SEQUENCE_GAP",
                "GENESIS_MISMATCH",
                "CHAIN_LINK_BROKEN",
                "CONTENT_HASH_MISMATCH",
                "CHAIN_HASH_MISMATCH",
            ].index(pair[1]),
        ),
    )


def system_event(
    config: AuditConfiguration,
    clock: FakeClock,
    api: Any,
    event_type: str,
    payload: dict[str, Any],
) -> dict[str, Any]:
    store = SqliteStore(config.db_path, LEDGER)
    with store.write_transaction() as connection:
        result: dict[str, Any] = api.append_service.append_system_event(
            connection, event_type, "admin", "AUDIT_EVENT", "target", payload
        )
        return result


def redaction_payload(target: dict[str, Any], paths: list[str]) -> dict[str, Any]:
    return {
        "targetSeq": target["seq"],
        "targetEventId": target["eventId"],
        "paths": paths,
        "reason": "privacy request",
        "ticketId": "T-1",
        "requestedBy": "admin",
    }


def test_validated_redaction_event_authorizes_missing_leaf(
    client: TestClient, config: AuditConfiguration, clock: FakeClock
) -> None:
    target = append(client, 1)[0]
    api = client.app.state.api  # type: ignore[attr-defined]
    system_event(
        config, clock, api, "RECORD_REDACTED", redaction_payload(target, ["/note"])
    )
    tamper(config, "DELETE FROM payload_leaves WHERE seq = 1 AND pointer = '/note'")

    report = verify(client)

    assert report["intact"] is True
    assert report["redactedFields"] == 1


@pytest.mark.parametrize(
    "mutate",
    [
        lambda p: p.update(targetEventId="wrong"),
        lambda p: p.update(paths=["/other"]),
        lambda p: p.update(extra="field"),
        lambda p: p.update(targetSeq=True),
        lambda p: p.update(paths=[]),
        lambda p: p.update(paths=["no-leading-slash"]),
    ],
    ids=["wrong-id", "other-path", "extra-key", "bool-seq", "no-paths", "bad-pointer"],
)
def test_malformed_authorization_grants_nothing(
    client: TestClient,
    config: AuditConfiguration,
    clock: FakeClock,
    mutate: Callable[[dict[str, Any]], None],
) -> None:
    target = append(client, 1)[0]
    api = client.app.state.api  # type: ignore[attr-defined]
    payload = redaction_payload(target, ["/note"])
    mutate(payload)
    system_event(config, clock, api, "RECORD_REDACTED", payload)
    tamper(config, "DELETE FROM payload_leaves WHERE seq = 1 AND pointer = '/note'")

    report = verify(client)

    assert report["intact"] is False
    assert ("UNAUTHORIZED_REDACTION", 1) in kinds(report)


def test_system_record_leaf_cannot_be_redacted_by_authorization(
    client: TestClient, config: AuditConfiguration, clock: FakeClock
) -> None:
    api = client.app.state.api  # type: ignore[attr-defined]
    target = append(client, 1)[0]
    first = system_event(
        config, clock, api, "RECORD_REDACTED", redaction_payload(target, ["/note"])
    )
    system_event(
        config,
        clock,
        api,
        "RECORD_REDACTED",
        redaction_payload(first, ["/reason"]),
    )
    tamper(config, "DELETE FROM payload_leaves WHERE seq = 2 AND pointer = '/reason'")

    report = verify(client)

    assert ("UNAUTHORIZED_REDACTION", 2) in kinds(report)


def archive_payload(
    last: dict[str, Any], first_seq: int, cutoff: str, retention_days: int
) -> dict[str, Any]:
    return {
        "archivedThroughSeq": last["seq"],
        "fromSeq": first_seq,
        "toSeq": last["seq"],
        "count": last["seq"] - first_seq + 1,
        "cutoff": cutoff,
        "retentionDays": retention_days,
        "lastArchivedChainHash": last["chainHash"],
        "archiveFile": "archive-1.json",
        "archiveSha256": "f" * 64,
        "archiveBundleId": "bundle-1",
        "requestedBy": "admin",
    }


def skeletonize(config: AuditConfiguration, through: int) -> None:
    tamper(
        config,
        f"DELETE FROM payload_leaves WHERE seq <= {through}",
        "UPDATE audit_events SET event_type = NULL, actor_id = NULL, "
        "resource_type = NULL, resource_id = NULL, occurred_at = NULL, "
        "source = NULL, payload_commitments = NULL, archived = 1, "
        f"archived_at = '2025-01-03T12:00:00.000000Z' WHERE seq <= {through}",
    )


def test_archive_authorization_is_cumulative_and_validated(
    client: TestClient, config: AuditConfiguration, clock: FakeClock
) -> None:
    api = client.app.state.api  # type: ignore[attr-defined]
    events = append(client, 3)
    clock.advance(days=2)
    system_event(
        config,
        clock,
        api,
        "RECORDS_ARCHIVED",
        archive_payload(events[1], 1, "2025-01-02T00:00:00Z", 1),
    )
    skeletonize(config, 2)

    report = verify(client)

    assert report["intact"] is True
    assert report["archivedRecords"] == 2
    assert report["checkedRecords"] == 4


def test_archived_skeleton_without_authorization_is_reported(
    client: TestClient, config: AuditConfiguration
) -> None:
    append(client, 3)
    skeletonize(config, 2)

    report = verify(client)

    assert {("UNAUTHORIZED_ARCHIVE", 1), ("UNAUTHORIZED_ARCHIVE", 2)} <= kinds(report)


def test_archive_that_violates_declared_retention_is_flagged(
    client: TestClient, config: AuditConfiguration, clock: FakeClock
) -> None:
    api = client.app.state.api  # type: ignore[attr-defined]
    events = append(client, 3)
    clock.advance(days=2)
    system_event(
        config,
        clock,
        api,
        "RECORDS_ARCHIVED",
        archive_payload(events[1], 1, "2025-01-03T00:00:00Z", 30),
    )
    skeletonize(config, 2)

    report = verify(client)

    assert ("RETENTION_POLICY_VIOLATION", 4) in kinds(report)
    assert report["archivedRecords"] == 2


def test_archive_event_with_wrong_end_hash_grants_nothing(
    client: TestClient, config: AuditConfiguration, clock: FakeClock
) -> None:
    api = client.app.state.api  # type: ignore[attr-defined]
    events = append(client, 3)
    clock.advance(days=2)
    payload = archive_payload(events[1], 1, "2025-01-02T00:00:00Z", 1)
    payload["lastArchivedChainHash"] = "0" * 64
    system_event(config, clock, api, "RECORDS_ARCHIVED", payload)
    skeletonize(config, 2)

    report = verify(client)

    assert ("UNAUTHORIZED_ARCHIVE", 1) in kinds(report)
    assert ("MALFORMED_RECORD", 4) in kinds(report)


def test_archived_row_with_retained_business_data_is_malformed(
    client: TestClient, config: AuditConfiguration
) -> None:
    append(client, 2)
    tamper(
        config,
        "UPDATE audit_events SET archived = 1, "
        "archived_at = '2025-01-03T12:00:00.000000Z' WHERE seq = 1",
    )

    assert ("MALFORMED_RECORD", 1) in kinds(verify(client))


def test_verify_succeeds_while_another_connection_holds_the_write_lock(
    client: TestClient, config: AuditConfiguration
) -> None:
    append(client, 3)
    writer = sqlite3.connect(config.db_path, isolation_level=None)
    try:
        writer.execute("BEGIN IMMEDIATE")
        report = verify(client)
    finally:
        writer.execute("ROLLBACK")
        writer.close()

    assert report["intact"] is True
    assert report["checkedRecords"] == 3


def test_verify_scans_one_snapshot_despite_concurrent_appends(
    client: TestClient, config: AuditConfiguration
) -> None:
    append(client, 3)
    api = client.app.state.api  # type: ignore[attr-defined]
    store = SqliteStore(config.db_path, LEDGER)
    verifier = LedgerVerifier(store, LEDGER, api.signer.public_key_base64)
    with store.read_snapshot() as snapshot:
        snapshot.execute("SELECT COUNT(*) FROM audit_events").fetchone()
        append(client, 2)
        report = verifier.verify_connection(snapshot)

    assert report["headSeq"] == 3
    assert report["intact"] is True
    assert verify(client)["headSeq"] == 5


def test_verifier_does_not_leak_sensitive_values(
    client: TestClient, config: AuditConfiguration
) -> None:
    append(client, 1, payload={"secret": "TOP-SECRET-VALUE"})
    tamper(
        config,
        "UPDATE payload_leaves SET value = '\"TOP-SECRET-VALUE-2\"' "
        "WHERE pointer = '/secret'",
    )

    response = client.get("/audit/verify", headers=AUDITOR)

    assert "TOP-SECRET" not in response.text
