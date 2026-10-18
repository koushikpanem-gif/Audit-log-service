#!/usr/bin/env python3
"""Synthetic-only tamper tool for demonstrating audit-log verification.

It edits a SQLite ledger directly (bypassing the service, as a DB administrator could) so the
verifier's detections and documented limits can be demonstrated. It refuses to touch any
ledger whose ledger_id does not start with "synthetic-" and requires an explicit flag.
Never point it at real or production data.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "python" / "src"))

from audit_log_service import v1_hashes  # noqa: E402

ACK = "--i-understand-this-is-synthetic-data"
GUARDS = (
    "audit_events_block_delete",
    "audit_events_archive_only_update",
    "payload_leaves_block_update",
    "checkpoints_block_update",
    "checkpoints_block_delete",
)


def connect(path: Path) -> sqlite3.Connection:
    if not path.is_file():
        raise SystemExit(f"database not found: {path}")
    connection = sqlite3.connect(path)
    row = connection.execute("SELECT ledger_id FROM ledger_meta").fetchone()
    if row is None or not str(row[0]).startswith("synthetic-"):
        connection.close()
        raise SystemExit("refusing: ledger_id must start with 'synthetic-'")
    connection.execute("PRAGMA foreign_keys = OFF")
    connection.execute("PRAGMA ignore_check_constraints = ON")
    for trigger in GUARDS:
        connection.execute(f"DROP TRIGGER IF EXISTS {trigger}")
    return connection


def rehash_from(connection: sqlite3.Connection, start: int, only_one: bool) -> None:
    """Recompute content/chain hashes; links are re-chained unless only_one is set."""
    previous: str | None = None
    rows = connection.execute(
        "SELECT seq, event_id, event_type, actor_id, resource_type, resource_id, occurred_at, "
        "recorded_at, source, payload_commitments, prev_hash FROM audit_events "
        "WHERE seq >= ? ORDER BY seq",
        (start,),
    ).fetchall()
    for seq, event_id, event_type, actor, rtype, rid, occurred, recorded, source, tree, prev in rows:
        prev_hash = previous if previous is not None and not only_one else prev
        content = v1_hashes.content_hash(
            v1_hashes.content_object(
                seq=seq,
                event_id=event_id,
                event_type=event_type,
                actor_id=actor,
                resource_type=rtype,
                resource_id=rid,
                occurred_at=occurred,
                timestamp=recorded,
                source=source,
                payload=json.loads(tree),
            )
        )
        chain = v1_hashes.chain_hash(prev_hash, content)
        connection.execute(
            "UPDATE audit_events SET content_hash=?, prev_hash=?, chain_hash=? WHERE seq=?",
            (content, prev_hash, chain, seq),
        )
        previous = chain
        if only_one:
            break


def run(args: argparse.Namespace) -> str:
    connection = connect(args.db)
    try:
        if args.mode == "edit-field":
            connection.execute("UPDATE audit_events SET actor_id = ? WHERE seq = ?", ("tampered", args.seq))
            if args.rehash:
                rehash_from(connection, args.seq, only_one=True)
        elif args.mode == "edit-leaf":
            connection.execute(
                "UPDATE payload_leaves SET value = '\"tampered\"' WHERE seq = ? AND pointer = ?",
                (args.seq, args.pointer),
            )
        elif args.mode == "delete":
            connection.execute("DELETE FROM payload_leaves WHERE seq = ?", (args.seq,))
            connection.execute("DELETE FROM audit_events WHERE seq = ?", (args.seq,))
        elif args.mode == "swap":
            connection.execute("UPDATE audit_events SET seq = -1 WHERE seq = ?", (args.seq,))
            connection.execute("UPDATE audit_events SET seq = ? WHERE seq = ?", (args.seq, args.seq + 1))
            connection.execute("UPDATE audit_events SET seq = ? WHERE seq = -1", (args.seq + 1,))
        elif args.mode == "rewrite":
            connection.execute("UPDATE audit_events SET actor_id = 'rewritten' WHERE seq >= ?", (args.seq,))
            rehash_from(connection, args.seq, only_one=False)
        elif args.mode == "truncate":
            connection.execute("DELETE FROM payload_leaves WHERE seq >= ?", (args.seq,))
            connection.execute("DELETE FROM audit_events WHERE seq >= ?", (args.seq,))
        elif args.mode == "delete-checkpoints":
            connection.execute("DELETE FROM checkpoints")
        connection.commit()
    finally:
        connection.close()
    return f"applied {args.mode} to {args.db}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("db", type=Path, help="path to a synthetic ledger SQLite file")
    parser.add_argument(
        "mode",
        choices=[
            "edit-field",
            "edit-leaf",
            "delete",
            "swap",
            "rewrite",
            "truncate",
            "delete-checkpoints",
        ],
    )
    parser.add_argument("--seq", type=int, default=1, help="target sequence (swap uses seq and seq+1)")
    parser.add_argument("--pointer", default="/", help="payload pointer for edit-leaf")
    parser.add_argument("--rehash", action="store_true", help="edit-field: recompute that row's hashes")
    parser.add_argument(ACK, dest="ack", action="store_true", required=True)
    args = parser.parse_args(argv)
    print(run(args))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
