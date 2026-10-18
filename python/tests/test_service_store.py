from __future__ import annotations

import json
import multiprocessing
import sqlite3
import threading
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from pathlib import Path
from typing import Any

import pytest
from concurrency_worker import append_many, environment
from conftest import ADMIN, READER, WRITER, FakeClock, event_body, make_config
from ledger_checks import assert_chain_valid
from starlette.testclient import TestClient

from audit_log_service.app import create_app
from audit_log_service.auth import ApiKeyAuthenticator
from audit_log_service.configuration import AuditConfiguration, ConfigurationError
from audit_log_service.ledger import AppendService, parse_append_request
from audit_log_service.store import (
    LedgerMismatchError,
    SqliteStore,
    StorageBusyError,
    StorageConflictError,
    _script,
)

LEDGER = "python-test-ledger"


def new_store(tmp_path: Path, ledger: str = LEDGER, **kwargs: Any) -> SqliteStore:
    return SqliteStore(tmp_path / "audit.db", ledger, **kwargs)


def service_for(tmp_path: Path, interval: str = "100") -> tuple[AppendService, Any]:
    config = make_config(tmp_path, AUDIT_CHECKPOINT_INTERVAL=interval)
    store = SqliteStore(config.db_path, config.ledger_id)
    return AppendService(store, config, config.load_signer()), config


def request(config: AuditConfiguration, resource_id: str = "r") -> Any:
    return parse_append_request(
        {
            "eventType": "T",
            "actorId": "a",
            "resourceType": "R",
            "resourceId": resource_id,
            "payload": {"k": "v"},
        },
        config,
    )


def test_connection_pragmas_and_schema_version(tmp_path: Path) -> None:
    store = new_store(tmp_path)

    with store.write_transaction() as connection:
        pragmas = {
            name: connection.execute(f"PRAGMA {name}").fetchone()[0]
            for name in (
                "journal_mode",
                "foreign_keys",
                "synchronous",
                "secure_delete",
                "busy_timeout",
                "user_version",
            )
        }
    assert pragmas == {
        "journal_mode": "wal",
        "foreign_keys": 1,
        "synchronous": 2,
        "secure_delete": 1,
        "busy_timeout": 30000,
        "user_version": 3,
    }
    with store.read_snapshot() as connection:
        assert connection.execute("PRAGMA query_only").fetchone()[0] == 1
        with pytest.raises(sqlite3.OperationalError):
            connection.execute("DELETE FROM checkpoints")
    names = {
        row[0]
        for row in sqlite3.connect(tmp_path / "audit.db").execute(
            "SELECT name FROM sqlite_master"
        )
    }
    assert {
        "audit_events",
        "payload_leaves",
        "checkpoints",
        "ledger_meta",
        "redaction_cleanup",
        "archive_jobs",
        "idx_audit_events_actor_seq",
        "idx_audit_events_resource_seq",
        "idx_audit_events_type_seq",
        "idx_audit_events_recorded_seq",
    } <= names


def test_ledger_binding_and_unsupported_databases_are_rejected(
    tmp_path: Path,
) -> None:
    new_store(tmp_path)
    new_store(tmp_path)  # reopening with the same ledger is fine
    with pytest.raises(LedgerMismatchError):
        new_store(tmp_path, ledger="another-ledger")

    foreign = tmp_path / "foreign.db"
    connection = sqlite3.connect(foreign)
    connection.execute("CREATE TABLE unrelated(x)")
    connection.commit()
    connection.close()
    with pytest.raises(LedgerMismatchError):
        SqliteStore(foreign, LEDGER)

    future = tmp_path / "future.db"
    store = SqliteStore(future, LEDGER)
    with store.write_transaction() as writer:
        writer.execute("PRAGMA user_version = 99")
    with pytest.raises(LedgerMismatchError):
        SqliteStore(future, LEDGER)


def test_explicit_migration_from_schema_v1_preserves_data(tmp_path: Path) -> None:
    path = tmp_path / "legacy.db"
    connection = sqlite3.connect(path, isolation_level=None)
    connection.execute("PRAGMA journal_mode = WAL")
    for statement in _script("schema-v1.sql"):
        connection.execute(statement)
    connection.execute(
        "INSERT INTO ledger_meta(singleton, ledger_id, schema_version) VALUES (1, ?, 1)",
        (LEDGER,),
    )
    connection.execute("PRAGMA user_version = 1")
    connection.close()

    store = SqliteStore(path, LEDGER)

    with store.read_snapshot() as reader:
        assert reader.execute("PRAGMA user_version").fetchone()[0] == 3
        assert (
            reader.execute("SELECT schema_version FROM ledger_meta").fetchone()[0] == 3
        )
        reader.execute("SELECT COUNT(*) FROM redaction_cleanup").fetchone()
        reader.execute("SELECT COUNT(*) FROM archive_jobs").fetchone()


def test_guard_triggers_block_accidental_writes(tmp_path: Path) -> None:
    service, config = service_for(tmp_path, interval="1")
    service.append(request(config), "writer")
    connection = sqlite3.connect(config.db_path)

    def blocked(sql: str) -> None:
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(sql)

    blocked("DELETE FROM audit_events WHERE seq = 1")
    blocked("UPDATE audit_events SET actor_id = 'x' WHERE seq = 1")
    blocked("UPDATE audit_events SET recorded_at = 'x', archived = 1 WHERE seq = 1")
    blocked("UPDATE payload_leaves SET value = '1' WHERE seq = 1")
    blocked("UPDATE checkpoints SET signature = 'x' WHERE seq = 1")
    blocked("DELETE FROM checkpoints WHERE seq = 1")
    connection.execute(
        "UPDATE audit_events SET archived = 1, archived_at = 'now', event_type = NULL, "
        "actor_id = NULL, resource_type = NULL, resource_id = NULL, "
        "occurred_at = NULL, source = NULL, payload_commitments = NULL WHERE seq = 1"
    )
    blocked("UPDATE audit_events SET archived = 0 WHERE seq = 1")
    connection.close()


def test_write_rolls_back_event_leaves_and_sequence_on_failure(tmp_path: Path) -> None:
    config = make_config(tmp_path, AUDIT_CHECKPOINT_INTERVAL="2")
    store = SqliteStore(config.db_path, config.ledger_id)
    real = config.load_signer()

    class FailingSigner:
        fail = True

        def sign_checkpoint(self, **kwargs: Any) -> Any:
            if self.fail:
                raise RuntimeError("signing unavailable")
            return real.sign_checkpoint(**kwargs)

    signer = FailingSigner()
    service = AppendService(store, config, signer)  # type: ignore[arg-type]
    service.append(request(config, "one"), "writer")

    with pytest.raises(RuntimeError):
        service.append(request(config, "two"), "writer")

    with store.read_snapshot() as reader:
        assert reader.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0] == 1
        assert reader.execute("SELECT COUNT(*) FROM payload_leaves").fetchone()[0] == 1
        assert reader.execute("SELECT COUNT(*) FROM checkpoints").fetchone()[0] == 0
    signer.fail = False
    assert service.append(request(config, "two"), "writer")["seq"] == 2
    assert assert_chain_valid(config.db_path, config.ledger_id) == 2


def test_duplicate_event_id_is_a_conflict_and_rolls_back(tmp_path: Path) -> None:
    config = make_config(tmp_path)
    store = SqliteStore(config.db_path, config.ledger_id)
    service = AppendService(
        store, config, config.load_signer(), event_id_source=lambda: "fixed-id"
    )
    service.append(request(config), "writer")

    with pytest.raises(StorageConflictError):
        service.append(request(config), "writer")
    assert assert_chain_valid(config.db_path, config.ledger_id) == 1


def test_restart_continues_the_chain_with_the_same_key(
    tmp_path: Path, clock: FakeClock
) -> None:
    config = make_config(tmp_path)
    first = TestClient(create_app(config, clock=clock), raise_server_exceptions=False)
    created = first.post("/audit/events", json=event_body(), headers=WRITER).json()
    key_before = first.get("/audit/public-key").json()
    first.close()

    second = TestClient(create_app(config, clock=clock), raise_server_exceptions=False)
    follow = second.post("/audit/events", json=event_body(), headers=WRITER).json()

    assert follow["seq"] == 2
    assert follow["prevHash"] == created["chainHash"]
    assert second.get("/audit/public-key").json() == key_before
    assert assert_chain_valid(config.db_path, config.ledger_id) == 2


def test_concurrent_threads_produce_one_gapless_chain(tmp_path: Path) -> None:
    service, config = service_for(tmp_path, interval="10")

    def work(label: int) -> list[int]:
        return [
            int(service.append(request(config, f"{label}-{i}"), f"w{label}")["seq"])
            for i in range(25)
        ]

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = [seq for batch in pool.map(work, range(8)) for seq in batch]

    assert sorted(results) == list(range(1, 201))
    assert assert_chain_valid(config.db_path, config.ledger_id) == 200
    with sqlite3.connect(config.db_path) as connection:
        checkpoints = [
            row[0]
            for row in connection.execute("SELECT seq FROM checkpoints ORDER BY seq")
        ]
    assert checkpoints == list(range(10, 201, 10))


def test_concurrent_processes_produce_one_gapless_chain(tmp_path: Path) -> None:
    db_path = str(tmp_path / "audit.db")
    key_dir = str(tmp_path / "keys")
    config = AuditConfiguration.from_environment(environment(db_path, key_dir, "10"))
    config.load_signer()  # create the dev key once before the writers race
    SqliteStore(config.db_path, config.ledger_id)

    context = multiprocessing.get_context("spawn")
    with ProcessPoolExecutor(max_workers=4, mp_context=context) as pool:
        futures = [
            pool.submit(append_many, db_path, key_dir, "10", f"p{n}", 20)
            for n in range(4)
        ]
        results = [seq for future in futures for seq in future.result(timeout=300)]

    assert sorted(results) == list(range(1, 81))
    assert assert_chain_valid(config.db_path, config.ledger_id) == 80
    with sqlite3.connect(config.db_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM checkpoints").fetchone()[0] == 8


def test_http_writers_and_readers_run_concurrently(
    config: AuditConfiguration, clock: FakeClock
) -> None:
    client = TestClient(create_app(config, clock=clock), raise_server_exceptions=False)
    errors: list[str] = []

    def writer(index: int) -> None:
        for n in range(10):
            response = client.post(
                "/audit/events",
                json=event_body(resourceId=f"{index}-{n}"),
                headers=WRITER,
            )
            if response.status_code != 201:
                errors.append(response.text)

    def reader() -> None:
        for _ in range(10):
            response = client.get("/audit/events", params={"limit": 5}, headers=READER)
            if response.status_code != 200:
                errors.append(response.text)

    threads = [threading.Thread(target=writer, args=(i,)) for i in range(4)]
    threads += [threading.Thread(target=reader) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert assert_chain_valid(config.db_path, config.ledger_id) == 40


def test_read_snapshot_ignores_later_commits(tmp_path: Path) -> None:
    service, config = service_for(tmp_path)
    store = SqliteStore(config.db_path, config.ledger_id)
    service.append(request(config, "one"), "writer")

    with store.read_snapshot() as reader:
        before = reader.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0]
        service.append(request(config, "two"), "writer")
        during = reader.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0]
    with store.read_snapshot() as reader:
        after = reader.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0]

    assert (before, during, after) == (1, 1, 2)


def test_busy_database_maps_to_503_without_data_and_readers_still_work(
    tmp_path: Path, clock: FakeClock
) -> None:
    config = make_config(tmp_path)
    client = TestClient(create_app(config, clock=clock), raise_server_exceptions=False)
    client.post("/audit/events", json=event_body(), headers=WRITER)
    # Shorten the wait for the HTTP writer by swapping in a short-timeout store.
    short = SqliteStore(config.db_path, config.ledger_id, busy_timeout_ms=100)
    holder = sqlite3.connect(config.db_path, isolation_level=None)
    holder.execute("BEGIN IMMEDIATE")
    try:
        service = AppendService(short, config, config.load_signer(), clock)
        with pytest.raises(StorageBusyError):
            service.append(request(config), "writer")
        with short.read_snapshot() as reader:
            assert (
                reader.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0] == 1
            )
    finally:
        holder.execute("ROLLBACK")
        holder.close()


def test_busy_error_is_returned_as_503(tmp_path: Path, clock: FakeClock) -> None:
    import audit_log_service.app as app_module

    config = make_config(tmp_path)
    holder_path = config.db_path
    original = app_module.SqliteStore

    def short_store(path: Path, ledger_id: str) -> SqliteStore:
        return original(path, ledger_id, busy_timeout_ms=100)

    app_module.SqliteStore = short_store  # type: ignore[misc,assignment]
    try:
        client = TestClient(
            create_app(config, clock=clock), raise_server_exceptions=False
        )
    finally:
        app_module.SqliteStore = original  # type: ignore[misc]
    holder = sqlite3.connect(holder_path, isolation_level=None)
    holder.execute("BEGIN IMMEDIATE")
    try:
        response = client.post("/audit/events", json=event_body(), headers=WRITER)
        checkpoint = client.post("/audit/admin/checkpoints", headers=ADMIN)
    finally:
        holder.execute("ROLLBACK")
        holder.close()

    assert response.status_code == 503
    assert response.json()["error"]["code"] == "STORAGE_BUSY"
    assert "dev-writer" not in response.text and "hello" not in response.text
    assert checkpoint.status_code == 503


def test_authenticator_rejects_ambiguous_and_prod_without_file(
    tmp_path: Path,
) -> None:
    authenticator = ApiKeyAuthenticator(make_config(tmp_path))
    assert authenticator.authenticate("dev-admin-only") is not None
    assert authenticator.authenticate("dev-admin-only ") is None
    assert authenticator.authenticate("DEV-ADMIN-ONLY") is None
    assert authenticator.authenticate(None) is None
    assert authenticator.authenticate("x" * 5000) is None
    admin = authenticator.authenticate("dev-admin-only")
    assert admin is not None and admin.roles == {"admin", "writer", "reader", "auditor"}

    with pytest.raises(ConfigurationError):
        make_config(tmp_path, AUDIT_ENV="prod")

    duplicate = tmp_path / "dup.json"
    digest = "a" * 64
    duplicate.write_text(
        json.dumps(
            {
                "a": {"keyHash": digest, "roles": ["writer"]},
                "b": {"keyHash": digest, "roles": ["reader"]},
            }
        )
    )
    with pytest.raises(ConfigurationError):
        ApiKeyAuthenticator(make_config(tmp_path, AUDIT_API_KEYS_FILE=str(duplicate)))
