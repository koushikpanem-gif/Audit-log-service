from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from audit_log_service.app import create_app
from audit_log_service.configuration import AuditConfiguration

WRITER = {"X-API-Key": "dev-writer-only"}
READER = {"X-API-Key": "dev-reader-only"}
AUDITOR = {"X-API-Key": "dev-auditor-only"}
ADMIN = {"X-API-Key": "dev-admin-only"}


class FakeClock:
    def __init__(self) -> None:
        self.now = datetime(2025, 1, 1, 12, 0, 0, 123456, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, **kwargs: float) -> None:
        self.now += timedelta(**kwargs)


def make_config(tmp_path: Path, **overrides: str) -> AuditConfiguration:
    values = {
        "AUDIT_ENV": "dev",
        "AUDIT_LEDGER_ID": "python-test-ledger",
        "AUDIT_DB_PATH": str(tmp_path / "audit.db"),
        "AUDIT_SIGNING_PRIVATE_KEY": str(tmp_path / "keys" / "private.pem"),
        "AUDIT_SIGNING_PUBLIC_KEY": str(tmp_path / "keys" / "public.b64"),
    }
    values.update(overrides)
    return AuditConfiguration.from_environment(values)


def event_body(**overrides: object) -> dict[str, object]:
    body: dict[str, object] = {
        "eventType": "DOCUMENT_VIEWED",
        "actorId": "alice",
        "resourceType": "DOCUMENT",
        "resourceId": "doc-1",
        "payload": {"note": "hello", "amount": "12.50", "tags": ["a", "b"]},
    }
    body.update(overrides)
    return body


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def config(tmp_path: Path) -> AuditConfiguration:
    return make_config(tmp_path)


@pytest.fixture
def client(config: AuditConfiguration, clock: FakeClock) -> TestClient:
    return TestClient(create_app(config, clock=clock), raise_server_exceptions=False)
