from __future__ import annotations

import json
from pathlib import Path

import pytest

from audit_log_service.configuration import AuditConfiguration, ConfigurationError
from audit_log_service.signing import CheckpointSigner

VALID_KEYS = {
    "sample-writer": {
        "keyHash": "a" * 64,
        "roles": ["writer"],
    }
}


def test_default_configuration_and_valid_production_configuration(
    tmp_path: Path,
) -> None:
    defaults = AuditConfiguration.from_environment({})
    assert defaults.environment == "dev"
    assert defaults.retention_days == 2555
    assert defaults.checkpoint_interval == 100
    assert (
        AuditConfiguration.from_environment(
            {"AUDIT_RETENTION_DAYS": "500000"}
        ).retention_days
        == 500_000
    )

    api_keys = tmp_path / "api-keys.json"
    api_keys.write_text(json.dumps(VALID_KEYS), encoding="utf-8")
    production = AuditConfiguration.from_environment(
        {
            "AUDIT_ENV": "prod",
            "AUDIT_API_KEYS_FILE": str(api_keys),
            "AUDIT_RETENTION_DAYS": "1",
        }
    )
    production.validate_api_keys()
    private_path = tmp_path / "signing-private.pem"
    public_path = tmp_path / "signing-public.b64"
    expected_signer = CheckpointSigner.from_files(
        private_path, public_path, environment="dev"
    )
    configured_production = AuditConfiguration.from_environment(
        {
            "AUDIT_ENV": "prod",
            "AUDIT_API_KEYS_FILE": str(api_keys),
            "AUDIT_RETENTION_DAYS": "1",
            "AUDIT_SIGNING_PRIVATE_KEY": str(private_path),
            "AUDIT_SIGNING_PUBLIC_KEY": str(public_path),
        }
    )
    assert configured_production.load_signer().key_id == expected_signer.key_id


@pytest.mark.parametrize(
    "value",
    [
        "0",
        "-1",
        "NaN",
        "Infinity",
        "-Infinity",
        "1e309",
        "1e-400",
        "1000000000000000",
        "500001",
        "not-a-number",
    ],
)
def test_retention_rejects_nonpositive_nonfinite_and_overflow(value: str) -> None:
    with pytest.raises(ConfigurationError, match="RETENTION_DAYS"):
        AuditConfiguration.from_environment({"AUDIT_RETENTION_DAYS": value})


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("AUDIT_ENV", "stage"),
        ("AUDIT_CHECKPOINT_INTERVAL", "0"),
        ("AUDIT_CHECKPOINT_INTERVAL", "1000001"),
        ("AUDIT_REQUEST_LIMIT_BYTES", "-1"),
        ("AUDIT_REQUEST_LIMIT_BYTES", "1048577"),
        ("AUDIT_PAYLOAD_LIMIT_BYTES", "262145"),
        ("AUDIT_MAX_DEPTH", "11"),
        ("AUDIT_MAX_LEAVES", "501"),
        ("AUDIT_LEDGER_ID", ""),
    ],
)
def test_environment_and_positive_count_or_size_bounds(name: str, value: str) -> None:
    with pytest.raises(ConfigurationError):
        AuditConfiguration.from_environment({name: value})


def test_production_requires_api_key_file_and_at_least_one_day() -> None:
    with pytest.raises(ConfigurationError, match="API_KEYS_FILE"):
        AuditConfiguration.from_environment({"AUDIT_ENV": "prod"})
    with pytest.raises(ConfigurationError, match="RETENTION_DAYS"):
        AuditConfiguration.from_environment(
            {
                "AUDIT_ENV": "prod",
                "AUDIT_API_KEYS_FILE": "api-keys.json",
                "AUDIT_RETENTION_DAYS": "0.5",
            }
        )


@pytest.mark.parametrize(
    "contents",
    [
        "{}",
        '{"reader":{"keyHash":"xyz","roles":["reader"]}}',
        '{"reader":{"keyHash":"' + "a" * 64 + '","roles":[]}}',
        '{"reader":{"keyHash":"' + "a" * 64 + '","roles":["root"]}}',
        '{"reader":{"keyHash":"'
        + "a" * 64
        + '","roles":["reader"],"apiKey":"secret"}}',
    ],
)
def test_api_key_file_rejects_invalid_hashes_shapes_and_roles(
    tmp_path: Path, contents: str
) -> None:
    api_keys = tmp_path / "api-keys.json"
    api_keys.write_text(contents, encoding="utf-8")
    config = AuditConfiguration.from_environment({"AUDIT_API_KEYS_FILE": str(api_keys)})
    with pytest.raises(ConfigurationError):
        config.validate_api_keys()


def test_production_signer_requires_files_and_valid_api_key_material(
    tmp_path: Path,
) -> None:
    api_keys = tmp_path / "api-keys.json"
    api_keys.write_text(json.dumps(VALID_KEYS), encoding="utf-8")
    config = AuditConfiguration.from_environment(
        {
            "AUDIT_ENV": "prod",
            "AUDIT_API_KEYS_FILE": str(api_keys),
            "AUDIT_SIGNING_PRIVATE_KEY": str(tmp_path / "private.pem"),
            "AUDIT_SIGNING_PUBLIC_KEY": str(tmp_path / "public.b64"),
        }
    )
    with pytest.raises(ConfigurationError, match="Unable to load"):
        config.load_signer()
