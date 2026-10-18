from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from importlib import resources
from pathlib import Path

SCHEMA_VERSION = 3
DEFAULT_BUSY_TIMEOUT_MS = 30_000
_BUSY_CODES = {5, 6}


class StorageError(Exception):
    """Raised for storage failures; messages never contain ledger data."""


class StorageBusyError(StorageError):
    """Raised when SQLite stays locked past the busy timeout."""


class LedgerMismatchError(StorageError):
    """Raised when the database is bound to a different ledger or schema."""


class StorageConflictError(StorageError):
    """Raised when a constraint or guard trigger rejects a change."""


@dataclass(frozen=True)
class WalCheckpoint:
    """Row of PRAGMA wal_checkpoint: busy flag, WAL frames, checkpointed frames."""

    busy: int
    log_frames: int
    checkpointed_frames: int

    @property
    def complete(self) -> bool:
        """True only when nothing blocked and the whole WAL was checkpointed."""
        return (
            self.busy == 0
            and self.log_frames >= 0
            and self.log_frames == self.checkpointed_frames
        )


def _translate(exc: sqlite3.Error) -> StorageError:
    code = getattr(exc, "sqlite_errorcode", None)
    if isinstance(code, int) and (code & 0xFF) in _BUSY_CODES:
        return StorageBusyError("Audit storage is busy")
    if isinstance(code, int) and (code & 0xFF) == 19:
        return StorageConflictError("The change conflicts with existing audit data")
    return StorageError("Audit storage operation failed")


def _script(name: str) -> list[str]:
    text = (
        resources.files("audit_log_service")
        .joinpath("sql", name)
        .read_text(encoding="utf-8")
    )
    statements: list[str] = []
    buffer = ""
    for line in text.splitlines(keepends=True):
        if not buffer and (not line.strip() or line.lstrip().startswith("--")):
            continue
        buffer += line
        if sqlite3.complete_statement(buffer):
            statements.append(buffer.strip())
            buffer = ""
    if buffer.strip():
        raise StorageError(f"Incomplete SQL statement in {name}")
    return statements


class SqliteStore:
    """Plain-sqlite3 adapter: WAL, synchronous=FULL, BEGIN IMMEDIATE writes."""

    def __init__(
        self,
        path: Path,
        ledger_id: str,
        *,
        busy_timeout_ms: int = DEFAULT_BUSY_TIMEOUT_MS,
        max_page_count: int | None = None,
    ) -> None:
        if busy_timeout_ms <= 0:
            raise ValueError("busy_timeout_ms must be positive")
        if max_page_count is not None and max_page_count <= 0:
            raise ValueError("max_page_count must be positive")
        # Test seam: a small page cap makes SQLite raise SQLITE_FULL without
        # filling a real disk. Production leaves it unset.
        self.max_page_count = max_page_count
        self._path = path
        self._ledger_id = ledger_id
        self._busy_timeout_ms = busy_timeout_ms
        path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    @property
    def ledger_id(self) -> str:
        return self._ledger_id

    def _connect(self, *, read_only: bool = False) -> sqlite3.Connection:
        try:
            connection = sqlite3.connect(
                self._path,
                timeout=self._busy_timeout_ms / 1000,
                isolation_level=None,
                check_same_thread=True,
            )
            connection.row_factory = sqlite3.Row
            connection.execute(f"PRAGMA busy_timeout = {self._busy_timeout_ms}")
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA secure_delete = ON")
            connection.execute("PRAGMA synchronous = FULL")
            if self.max_page_count is not None:
                connection.execute(
                    f"PRAGMA max_page_count = {int(self.max_page_count)}"
                )
            if read_only:
                connection.execute("PRAGMA query_only = ON")
        except sqlite3.Error as exc:
            raise _translate(exc) from exc
        return connection

    def _initialize(self) -> None:
        connection = self._connect()
        try:
            mode = connection.execute("PRAGMA journal_mode = WAL").fetchone()[0]
            if str(mode).lower() != "wal":
                raise StorageError("SQLite WAL mode is unavailable")
            connection.execute("BEGIN IMMEDIATE")
            try:
                self._prepare_schema(connection)
                connection.execute("COMMIT")
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
        except sqlite3.Error as exc:
            raise _translate(exc) from exc
        finally:
            connection.close()

    def _prepare_schema(self, connection: sqlite3.Connection) -> None:
        version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        if version == 0:
            tables = connection.execute(
                "SELECT COUNT(*) FROM sqlite_master "
                "WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
            ).fetchone()[0]
            if tables:
                raise LedgerMismatchError("Database is not an initialized audit ledger")
            for statement in _script("schema-v1.sql"):
                connection.execute(statement)
            connection.execute(
                "INSERT INTO ledger_meta(singleton, ledger_id, schema_version) "
                "VALUES (1, ?, 1)",
                (self._ledger_id,),
            )
            connection.execute("PRAGMA user_version = 1")
            version = 1
        if version == 1:
            for statement in _script("migration-v1-to-v2.sql"):
                connection.execute(statement)
            connection.execute("PRAGMA user_version = 2")
            version = 2
        if version == 2:
            for statement in _script("migration-v2-to-v3.sql"):
                connection.execute(statement)
            connection.execute("PRAGMA user_version = 3")
            version = 3
        if version != SCHEMA_VERSION:
            raise LedgerMismatchError("Unsupported audit database schema version")
        row = connection.execute(
            "SELECT ledger_id, schema_version FROM ledger_meta WHERE singleton = 1"
        ).fetchone()
        if row is None or row["schema_version"] != SCHEMA_VERSION:
            raise LedgerMismatchError("Ledger metadata does not match the schema")
        if row["ledger_id"] != self._ledger_id:
            raise LedgerMismatchError("Database belongs to a different ledger")

    def checkpoint_wal_truncate(self, busy_timeout_ms: int) -> WalCheckpoint:
        """Run PRAGMA wal_checkpoint(TRUNCATE) and return its result tuple.

        SQLite reports a checkpoint blocked by a reader as busy=1 in the returned
        row rather than raising, so callers must inspect the tuple.
        """
        if busy_timeout_ms <= 0:
            raise ValueError("busy_timeout_ms must be positive")
        connection = self._connect()
        try:
            connection.execute(f"PRAGMA busy_timeout = {busy_timeout_ms}")
            row = connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
            if row is None:
                raise StorageError("wal_checkpoint returned no result row")
            return WalCheckpoint(int(row[0]), int(row[1]), int(row[2]))
        except sqlite3.Error as exc:
            translated = _translate(exc)
            if isinstance(translated, StorageBusyError):
                return WalCheckpoint(1, -1, -1)
            raise translated from exc
        finally:
            connection.close()

    @contextmanager
    def write_transaction(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            try:
                yield connection
                connection.execute("COMMIT")
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
        except sqlite3.Error as exc:
            raise _translate(exc) from exc
        finally:
            connection.close()

    @contextmanager
    def read_snapshot(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect(read_only=True)
        try:
            connection.execute("BEGIN")
            try:
                yield connection
            finally:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
        except sqlite3.Error as exc:
            raise _translate(exc) from exc
        finally:
            connection.close()
