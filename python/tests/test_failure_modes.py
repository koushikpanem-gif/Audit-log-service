"""Bounded failure simulation: disk-full, slow I/O, busy writers.

Nothing here fills a real disk or asserts a throughput figure. Disk-full uses
SQLite's max_page_count; slow I/O adds a fixed sleep inside the write
transaction; busy uses a held write lock with a short busy timeout.
"""

from __future__ import annotations

import sqlite3
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from conftest import READER, WRITER, FakeClock, make_config
from ledger_checks import assert_chain_valid
from starlette.testclient import TestClient

from audit_log_service.app import create_app
from audit_log_service.ledger import AppendService, parse_append_request
from audit_log_service.store import (
    SqliteStore,
    StorageBusyError,
    StorageError,
)


def big_request(config: Any, index: int) -> Any:
    return parse_append_request(
        {
            "eventType": "T",
            "actorId": "a",
            "resourceType": "R",
            "resourceId": f"r{index}",
            "payload": {f"k{n}": "x" * 200 for n in range(40)},
        },
        config,
    )


def page_count(path: Path) -> int:
    connection = sqlite3.connect(path)
    try:
        return int(connection.execute("PRAGMA page_count").fetchone()[0])
    finally:
        connection.close()


def event_count(path: Path) -> int:
    connection = sqlite3.connect(path)
    try:
        return int(
            connection.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0]
        )
    finally:
        connection.close()


def test_disk_full_rolls_back_leaves_ledger_intact_and_resumes(
    tmp_path: Path, clock: FakeClock
) -> None:
    config = make_config(tmp_path, AUDIT_CHECKPOINT_INTERVAL="1000")
    store = SqliteStore(config.db_path, config.ledger_id)
    service = AppendService(store, config, config.load_signer(), clock)
    for index in range(3):
        service.append(big_request(config, index), "writer")
    store.max_page_count = page_count(config.db_path) + 5  # a few pages of headroom

    committed = 3
    failure: StorageError | None = None
    for index in range(3, 200):
        try:
            service.append(big_request(config, index), "writer")
        except StorageError as error:
            failure = error
            break
        committed += 1
    assert failure is not None, "page cap never reached"
    assert not isinstance(failure, StorageBusyError)
    assert str(failure) == "Audit storage operation failed"  # no internals leaked

    # The failed write rolled back completely: no partial event, no seq gap.
    assert event_count(config.db_path) == committed
    assert assert_chain_valid(config.db_path, config.ledger_id) == committed

    # Reads keep working while the store is full.
    with store.read_snapshot() as reader:
        assert reader.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0] == (
            committed
        )

    # Lifting the limit lets appends resume contiguously.
    store.max_page_count = None
    service.append(big_request(config, 999), "writer")
    assert assert_chain_valid(config.db_path, config.ledger_id) == committed + 1


def test_disk_full_over_http_is_a_generic_500_without_internals(
    tmp_path: Path, clock: FakeClock
) -> None:
    import audit_log_service.app as app_module

    config = make_config(tmp_path, AUDIT_CHECKPOINT_INTERVAL="1000")
    original = app_module.SqliteStore
    created: list[SqliteStore] = []

    def capped(path: Path, ledger_id: str) -> SqliteStore:
        store = original(path, ledger_id)
        created.append(store)
        return store

    app_module.SqliteStore = capped  # type: ignore[misc,assignment]
    try:
        client = TestClient(
            create_app(config, clock=clock), raise_server_exceptions=False
        )
    finally:
        app_module.SqliteStore = original  # type: ignore[misc]
    body = {
        "eventType": "T",
        "actorId": "a",
        "resourceType": "R",
        "resourceId": "r",
        "payload": {f"k{n}": "x" * 200 for n in range(40)},
    }
    assert client.post("/audit/events", json=body, headers=WRITER).status_code == 201
    created[0].max_page_count = page_count(config.db_path) + 3

    statuses = []
    for _ in range(100):
        response = client.post("/audit/events", json=body, headers=WRITER)
        statuses.append(response.status_code)
        if response.status_code != 201:
            break
    assert statuses[-1] == 500
    assert response.json()["error"]["code"] == "INTERNAL_ERROR"
    assert "SQLITE" not in response.text and "database" not in response.text.lower()
    assert client.get("/audit/events", headers=READER).status_code == 200
    assert event_count(config.db_path) == statuses.count(201) + 1


class SlowStore(SqliteStore):
    """Adds fixed latency to every write transaction, as a slow disk would."""

    delay_seconds = 0.05

    @contextmanager
    def write_transaction(self) -> Iterator[sqlite3.Connection]:
        with super().write_transaction() as connection:
            time.sleep(self.delay_seconds)
            yield connection


def test_slow_io_concurrent_writers_all_succeed_in_order(
    tmp_path: Path, clock: FakeClock
) -> None:
    config = make_config(tmp_path, AUDIT_CHECKPOINT_INTERVAL="1000")
    store = SlowStore(config.db_path, config.ledger_id)
    service = AppendService(store, config, config.load_signer(), clock)
    writers, per_writer = 4, 3
    errors: list[BaseException] = []

    def work(worker: int) -> None:
        try:
            for index in range(per_writer):
                service.append(big_request(config, worker * 100 + index), "writer")
        except BaseException as error:  # noqa: BLE001 - collected and asserted below
            errors.append(error)

    threads = [threading.Thread(target=work, args=(w,)) for w in range(writers)]
    started = time.perf_counter()
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    elapsed = time.perf_counter() - started

    assert errors == []
    total = writers * per_writer
    assert assert_chain_valid(config.db_path, config.ledger_id) == total
    # Single writer: latency inside the transaction is paid serially. This is a
    # lower bound implied by BEGIN IMMEDIATE, not a performance gate.
    assert elapsed >= total * SlowStore.delay_seconds * 0.9


def test_busy_writers_fail_fast_with_503_class_error_then_recover(
    tmp_path: Path, clock: FakeClock
) -> None:
    config = make_config(tmp_path, AUDIT_CHECKPOINT_INTERVAL="1000")
    SqliteStore(config.db_path, config.ledger_id)  # create schema
    short = SqliteStore(config.db_path, config.ledger_id, busy_timeout_ms=100)
    service = AppendService(short, config, config.load_signer(), clock)
    holder = sqlite3.connect(config.db_path, isolation_level=None)
    holder.execute("BEGIN IMMEDIATE")
    outcomes: list[str] = []
    guard = threading.Lock()

    def attempt(index: int) -> None:
        try:
            service.append(big_request(config, index), "writer")
            result = "ok"
        except StorageBusyError:
            result = "busy"
        with guard:
            outcomes.append(result)

    try:
        threads = [threading.Thread(target=attempt, args=(i,)) for i in range(6)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30)
            assert not thread.is_alive(), "writer hung instead of failing busy"
    finally:
        holder.execute("ROLLBACK")
        holder.close()

    assert outcomes == ["busy"] * 6
    assert event_count(config.db_path) == 0
    service.append(big_request(config, 100), "writer")
    assert assert_chain_valid(config.db_path, config.ledger_id) == 1
