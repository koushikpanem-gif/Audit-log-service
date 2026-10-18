"""Shared support for end-to-end tests that run the real services as OS processes.

Both services are started exactly as an operator would: the Java jar with `java -jar`
and the Python service with `uvicorn`. Each gets its own SQLite database, key and
archive directories under an isolated temporary home. Test keys are synthetic.

On Windows `Popen.kill()` is an abrupt TerminateProcess, so every restart in these
tests is a crash restart; there is no graceful-shutdown path being exercised.
"""

from __future__ import annotations

import os
import shutil
import socket
import sqlite3
import subprocess
import sys
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx2 as httpx

from audit_log_service.configuration import AuditConfiguration
from audit_log_service.ledger import AppendService, parse_append_request
from audit_log_service.store import SqliteStore

ROOT = Path(__file__).resolve().parents[2]
PYTHON_DIR = ROOT / "python"
JAR = ROOT / "java" / "target" / "audit-log-service-0.1.0-SNAPSHOT.jar"
LEDGER = "e2e-ledger"

WRITER = {"X-API-Key": "dev-writer-only"}
READER = {"X-API-Key": "dev-reader-only"}
AUDITOR = {"X-API-Key": "dev-auditor-only"}
ADMIN = {"X-API-Key": "dev-admin-only"}

KINDS = ["python", "java"]


def java_available() -> bool:
    return shutil.which("java") is not None and JAR.is_file()


def home_env(home: Path, ledger: str = LEDGER, **extra: str) -> dict[str, str]:
    env = {
        "AUDIT_ENV": "dev",
        "AUDIT_LEDGER_ID": ledger,
        "AUDIT_DB_PATH": str(home / "audit.db"),
        "AUDIT_SIGNING_PRIVATE_KEY": str(home / "keys" / "private.pem"),
        "AUDIT_SIGNING_PUBLIC_KEY": str(home / "keys" / "public.b64"),
        "AUDIT_ARCHIVE_DIR": str(home / "archives"),
        "AUDIT_EXPORT_DIR": str(home / "exports"),
    }
    env.update(extra)
    return env


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port: int = sock.getsockname()[1]
        return port


class ServiceProcess:
    """One running service process bound to one home directory (one database)."""

    def __init__(
        self, kind: str, home: Path, ledger: str = LEDGER, **extra_env: str
    ) -> None:
        self.kind = kind
        self.home = home
        self.env = home_env(home, ledger, **extra_env)
        self.port = 0
        self.process: subprocess.Popen[bytes] | None = None
        self.client: httpx.Client | None = None
        self._starts = 0

    @property
    def db_path(self) -> Path:
        return self.home / "audit.db"

    def _command(self) -> list[str]:
        if self.kind == "java":
            (self.home / "tmp").mkdir(exist_ok=True)
            return [
                "java",
                f"-Djava.io.tmpdir={self.home / 'tmp'}",
                "-jar",
                str(JAR),
                f"--server.port={self.port}",
            ]
        return [
            sys.executable,
            "-m",
            "uvicorn",
            "audit_log_service.app:create_app",
            "--factory",
            "--host",
            "127.0.0.1",
            "--port",
            str(self.port),
            "--log-level",
            "warning",
        ]

    def start(self, timeout: float = 120) -> ServiceProcess:
        assert self.process is None, "already running"
        self.home.mkdir(parents=True, exist_ok=True)
        self.port = free_port()
        self._starts += 1
        log = (self.home / f"{self.kind}-{self._starts}.log").open("wb")
        self.process = subprocess.Popen(  # noqa: S603
            self._command(),
            cwd=PYTHON_DIR,
            env={**os.environ, **self.env},
            stdout=log,
            stderr=subprocess.STDOUT,
        )
        self.client = httpx.Client(base_url=f"http://127.0.0.1:{self.port}", timeout=90)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                log.flush()
                tail = (self.home / f"{self.kind}-{self._starts}.log").read_text(
                    errors="replace"
                )[-3000:]
                raise RuntimeError(f"{self.kind} service exited at startup:\n{tail}")
            try:
                if self.client.get("/health").status_code == 200:
                    return self
            except httpx.TransportError:
                time.sleep(0.25)
        raise RuntimeError(f"{self.kind} service did not become healthy")

    def kill(self) -> None:
        if self.client is not None:
            self.client.close()
            self.client = None
        if self.process is not None:
            self.process.kill()
            self.process.wait(30)
            self.process = None

    def restart(self) -> ServiceProcess:
        self.kill()
        return self.start()

    def http(self) -> httpx.Client:
        assert self.client is not None
        return self.client

    def get(self, path: str, headers: dict[str, str] | None = None, **kw: Any) -> Any:
        return self.http().get(path, headers=headers or AUDITOR, **kw)

    def post(
        self, path: str, json: Any = None, headers: dict[str, str] | None = None
    ) -> Any:
        return self.http().post(path, json=json, headers=headers or WRITER)

    def append(self, **overrides: Any) -> dict[str, Any]:
        body = {
            "eventType": "DOCUMENT_VIEWED",
            "actorId": "alice",
            "resourceType": "DOCUMENT",
            "resourceId": "doc-1",
            "payload": {"note": "hello", "amount": "12.50", "tags": ["a", "b"]},
        }
        body.update(overrides)
        response = self.post("/audit/events", body)
        assert response.status_code == 201, response.text
        result: dict[str, Any] = response.json()
        return result

    def public_key(self) -> str:
        key: str = self.http().get("/audit/public-key").json()["publicKey"]
        return key

    def verify(self) -> dict[str, Any]:
        response = self.get("/audit/verify")
        assert response.status_code == 200, response.text
        report: dict[str, Any] = response.json()
        return report


def violations(report: dict[str, Any]) -> set[tuple[str, int | None]]:
    return {(item["type"], item["seq"]) for item in report["violations"]}


def build_offline_ledger(
    home: Path,
    events: int,
    ledger: str = LEDGER,
    checkpoint: bool = True,
    age_days: float = 0,
) -> tuple[AuditConfiguration, AppendService, list[dict[str, Any]]]:
    """Create a ledger with the Python library, no server running.

    Used to prepare synthetic databases that both services then open and verify.
    `age_days` back-dates recordedAt so archive retention can be exercised for real.
    """
    config = AuditConfiguration.from_environment(home_env(home, ledger))
    signer = config.load_signer()
    start = datetime.now(UTC) - timedelta(days=age_days)
    tick = iter(range(10_000_000))
    jump = [timedelta(0)]

    def clock() -> datetime:
        return start + jump[0] + timedelta(milliseconds=next(tick))

    service = AppendService(
        SqliteStore(config.db_path, config.ledger_id), config, signer, clock=clock
    )
    service.advance_clock = lambda days: jump.__setitem__(0, timedelta(days=days))  # type: ignore[attr-defined]
    created = []
    for index in range(events):
        request = parse_append_request(
            {
                "eventType": "DOCUMENT_VIEWED",
                "actorId": "alice",
                "resourceType": "DOCUMENT",
                "resourceId": f"doc-{index}",
                "payload": {"note": f"secret-{index}", "amount": "12.50"},
            },
            config,
        )
        created.append(service.append(request, "writer"))
    if checkpoint:
        service.create_checkpoint()
    return config, service, created


def raw_sql(db_path: Path, *statements: str) -> None:
    """Act as a database administrator: drop guard triggers, then run raw SQL."""
    connection = sqlite3.connect(db_path)
    connection.execute("PRAGMA ignore_check_constraints = ON")
    for (name,) in connection.execute(
        "SELECT name FROM sqlite_master WHERE type = 'trigger'"
    ).fetchall():
        connection.execute(f"DROP TRIGGER {name}")
    for statement in statements:
        connection.execute(statement)
    connection.commit()
    connection.close()


def run_verifier(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603
        [sys.executable, "-m", "audit_log_service.verifier", *args],
        cwd=PYTHON_DIR,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
