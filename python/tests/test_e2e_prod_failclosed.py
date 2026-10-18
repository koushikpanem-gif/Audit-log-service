"""Real-process proof that production mode fails closed in both services."""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from e2e_support import KINDS, ServiceProcess, java_available

pytestmark = pytest.mark.e2e


@pytest.fixture(params=KINDS)
def kind(request: pytest.FixtureRequest) -> str:
    if request.param == "java" and not java_available():
        pytest.skip("java or built jar not available")
    return str(request.param)


def _write_api_keys(path: Path) -> None:
    digest = hashlib.sha256(b"prod-test-admin-key").hexdigest()
    path.write_text(
        json.dumps({"ops-admin": {"keyHash": digest, "roles": ["admin"]}}),
        encoding="utf-8",
    )


def _write_signing_keys(keys: Path) -> None:
    keys.mkdir(parents=True, exist_ok=True)
    private = Ed25519PrivateKey.generate()
    (keys / "private.pem").write_bytes(
        private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    raw = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    (keys / "public.b64").write_text(base64.b64encode(raw).decode("ascii"))


def _expect_startup_failure(service: ServiceProcess) -> None:
    with pytest.raises(RuntimeError, match="exited at startup"):
        service.start(timeout=90)


def test_prod_without_api_keys_file_refuses_to_start(kind: str, tmp_path: Path) -> None:
    _write_signing_keys(tmp_path / "keys")
    _expect_startup_failure(ServiceProcess(kind, tmp_path, AUDIT_ENV="prod"))


def test_prod_without_signing_key_refuses_to_start_and_creates_none(
    kind: str, tmp_path: Path
) -> None:
    keys_file = tmp_path / "api-keys.json"
    _write_api_keys(keys_file)
    service = ServiceProcess(
        kind, tmp_path, AUDIT_ENV="prod", AUDIT_API_KEYS_FILE=str(keys_file)
    )
    _expect_startup_failure(service)
    assert not (tmp_path / "keys" / "private.pem").exists()
    assert not (tmp_path / "keys" / "public.b64").exists()


def test_prod_with_sub_day_retention_refuses_to_start(
    kind: str, tmp_path: Path
) -> None:
    keys_file = tmp_path / "api-keys.json"
    _write_api_keys(keys_file)
    _write_signing_keys(tmp_path / "keys")
    service = ServiceProcess(
        kind,
        tmp_path,
        AUDIT_ENV="prod",
        AUDIT_API_KEYS_FILE=str(keys_file),
        AUDIT_RETENTION_DAYS="0",
    )
    _expect_startup_failure(service)


def test_prod_started_from_provisioned_material(kind: str, tmp_path: Path) -> None:
    from test_provision_keys import load

    issued = load().provision(tmp_path / "keys", {"ops": "admin"})
    service = ServiceProcess(
        kind,
        tmp_path,
        AUDIT_ENV="prod",
        AUDIT_API_KEYS_FILE=str(tmp_path / "keys" / "api-keys.json"),
        AUDIT_SIGNING_PRIVATE_KEY=str(tmp_path / "keys" / "signing-private.pem"),
        AUDIT_SIGNING_PUBLIC_KEY=str(tmp_path / "keys" / "signing-public.b64"),
    )
    try:
        service.start()
        ok = service.get("/audit/events", headers={"X-API-Key": issued["ops"]})
        assert ok.status_code == 200
    finally:
        service.kill()


def test_prod_with_valid_material_starts_and_rejects_dev_sample_keys(
    kind: str, tmp_path: Path
) -> None:
    keys_file = tmp_path / "api-keys.json"
    _write_api_keys(keys_file)
    _write_signing_keys(tmp_path / "keys")
    service = ServiceProcess(
        kind, tmp_path, AUDIT_ENV="prod", AUDIT_API_KEYS_FILE=str(keys_file)
    )
    try:
        service.start()
        assert service.get("/audit/events").status_code == 401
        assert (
            service.get(
                "/audit/events", headers={"X-API-Key": "dev-admin-only"}
            ).status_code
            == 401
        )
        ok = service.get("/audit/events", headers={"X-API-Key": "prod-test-admin-key"})
        assert ok.status_code == 200
    finally:
        service.kill()
