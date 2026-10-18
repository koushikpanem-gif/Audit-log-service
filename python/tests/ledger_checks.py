from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any, cast

from audit_log_service.canonical_json import parse_json
from audit_log_service.payload_commitments import PayloadLeaf, reveal_payload
from audit_log_service.v1_hashes import (
    chain_hash,
    content_hash,
    content_object,
    genesis_hash,
)


def assert_chain_valid(db_path: Path, ledger_id: str) -> int:
    """Recompute every hash from raw rows; returns the number of events."""
    connection = sqlite3.connect(db_path)
    connection.row_factory = sqlite3.Row
    try:
        previous = genesis_hash(ledger_id)
        expected_seq = 0
        last_recorded = ""
        for row in connection.execute("SELECT * FROM audit_events ORDER BY seq"):
            expected_seq += 1
            assert row["seq"] == expected_seq
            assert row["prev_hash"] == previous
            commitments = parse_json(row["payload_commitments"])
            assert isinstance(commitments, dict)
            leaves = {
                leaf["pointer"]: PayloadLeaf(
                    bytes.fromhex(leaf["salt"]), cast(Any, parse_json(leaf["value"]))
                )
                for leaf in connection.execute(
                    "SELECT * FROM payload_leaves WHERE seq = ?", (row["seq"],)
                )
            }
            assert reveal_payload(commitments, leaves).redacted_paths == []
            content = content_object(
                seq=row["seq"],
                event_id=row["event_id"],
                event_type=row["event_type"],
                actor_id=row["actor_id"],
                resource_type=row["resource_type"],
                resource_id=row["resource_id"],
                occurred_at=row["occurred_at"],
                timestamp=row["recorded_at"],
                source=row["source"],
                payload=commitments,
            )
            digest = content_hash(cast(Any, content))
            assert row["content_hash"] == digest
            assert row["chain_hash"] == chain_hash(previous, digest)
            assert row["recorded_at"] >= last_recorded
            last_recorded = row["recorded_at"]
            previous = row["chain_hash"]
        return expected_seq
    finally:
        connection.close()
