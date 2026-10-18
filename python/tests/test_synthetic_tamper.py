from __future__ import annotations

import importlib.util
import sqlite3
from pathlib import Path
from types import ModuleType

import pytest

from audit_log_service import v1_hashes

ROOT = Path(__file__).resolve().parents[2]
RECORDED = "2026-01-02T03:04:05.123456Z"


def load_tool() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "synthetic_tamper", ROOT / "scripts" / "synthetic_tamper.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def build_ledger(path: Path, ledger_id: str, count: int = 3) -> None:
    schema = (
        ROOT / "java" / "src" / "main" / "resources" / "db" / "schema-v1.sql"
    ).read_text("utf-8")
    connection = sqlite3.connect(path)
    connection.executescript(schema)
    connection.execute("INSERT INTO ledger_meta VALUES (1, ?, 1)", (ledger_id,))
    previous = v1_hashes.genesis_hash(ledger_id)
    for seq in range(1, count + 1):
        content = v1_hashes.content_hash(
            v1_hashes.content_object(
                seq=seq,
                event_id=f"event-{seq}",
                event_type="EVENT",
                actor_id="actor",
                resource_type="ACCOUNT",
                resource_id="account-1",
                occurred_at=None,
                timestamp=RECORDED,
                source="writer",
                payload={},
            )
        )
        chain = v1_hashes.chain_hash(previous, content)
        connection.execute(
            "INSERT INTO audit_events(seq, event_id, event_type, actor_id, "
            "resource_type, resource_id, occurred_at, recorded_at, source, "
            "payload_commitments, hash_version, content_hash, prev_hash, chain_hash) "
            "VALUES (?, ?, 'EVENT', 'actor', 'ACCOUNT', 'account-1', NULL, ?, "
            "'writer', '{}', 1, ?, ?, ?)",
            (seq, f"event-{seq}", RECORDED, content, previous, chain),
        )
        previous = chain
    connection.commit()
    connection.close()


def rows(path: Path) -> list[tuple[int, str, str, str, str]]:
    connection = sqlite3.connect(path)
    try:
        return connection.execute(
            "SELECT seq, actor_id, content_hash, prev_hash, chain_hash "
            "FROM audit_events ORDER BY seq"
        ).fetchall()
    finally:
        connection.close()


def test_refuses_non_synthetic_ledgers(tmp_path: Path) -> None:
    database = tmp_path / "real.db"
    build_ledger(database, "production-ledger")
    tool = load_tool()
    with pytest.raises(SystemExit):
        tool.main([str(database), "truncate", "--seq", "2", tool.ACK])
    assert len(rows(database)) == 3


def test_requires_explicit_acknowledgement(tmp_path: Path) -> None:
    database = tmp_path / "synthetic.db"
    build_ledger(database, "synthetic-demo")
    with pytest.raises(SystemExit):
        load_tool().main([str(database), "truncate", "--seq", "2"])
    assert len(rows(database)) == 3


def test_edit_with_rehash_keeps_the_row_self_consistent_but_breaks_the_next_link(
    tmp_path: Path,
) -> None:
    database = tmp_path / "synthetic.db"
    build_ledger(database, "synthetic-demo")
    tool = load_tool()
    assert (
        tool.main([str(database), "edit-field", "--seq", "2", "--rehash", tool.ACK])
        == 0
    )
    stored = rows(database)
    assert stored[1][1] == "tampered"
    assert stored[1][4] != stored[2][3]
    assert stored[0][4] == stored[1][3]


def test_rewrite_rechains_every_later_row_and_truncate_removes_the_tail(
    tmp_path: Path,
) -> None:
    database = tmp_path / "synthetic.db"
    build_ledger(database, "synthetic-demo", count=4)
    tool = load_tool()
    tool.main([str(database), "rewrite", "--seq", "2", tool.ACK])
    stored = rows(database)
    assert all(stored[index][4] == stored[index + 1][3] for index in range(3))
    tool.main([str(database), "truncate", "--seq", "3", tool.ACK])
    assert [row[0] for row in rows(database)] == [1, 2]
