from __future__ import annotations

import base64
import json
import os
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key

from audit_log_service.signing import CheckpointSigner, SigningKeyError

FIXTURE_PATH = (
    Path(__file__).resolve().parents[2]
    / "docs"
    / "test-vectors"
    / "ed25519-checkpoint-v1.json"
)


@pytest.fixture
def fixture() -> dict[str, object]:
    return json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


def test_fixed_test_only_checkpoint_signature_matches_shared_fixture(
    fixture: dict[str, object],
) -> None:
    assert "TEST ONLY" in fixture["fixtureLabel"]
    signer = CheckpointSigner.from_pem(
        str(fixture["privateKeyPkcs8Pem"]).encode(),
        str(fixture["publicKeyBase64"]),
    )
    message = fixture["message"]
    assert isinstance(message, dict)
    signed = signer.sign_checkpoint(
        ledger_id=str(message["ledgerId"]),
        seq=int(message["seq"]),
        chain_hash=str(message["chainHash"]),
        created_at=str(message["createdAt"]),
    )
    assert signed.key_id == fixture["keyId"]
    assert signed.signature == fixture["signatureBase64"]
    assert signed.as_dict() == {
        **message,
        "keyId": fixture["keyId"],
        "signature": fixture["signatureBase64"],
    }
    assert CheckpointSigner.verify_checkpoint(
        signed.as_dict(), str(fixture["publicKeyBase64"])
    )


def test_checkpoint_wrong_key_and_malformed_fields_are_rejected(
    fixture: dict[str, object],
) -> None:
    message = fixture["message"]
    assert isinstance(message, dict)
    signer = CheckpointSigner.from_pem(
        str(fixture["privateKeyPkcs8Pem"]).encode(),
        str(fixture["publicKeyBase64"]),
    )
    signed = signer.sign_checkpoint(
        ledger_id=str(message["ledgerId"]),
        seq=int(message["seq"]),
        chain_hash=str(message["chainHash"]),
        created_at=str(message["createdAt"]),
    )
    other_key = Ed25519PrivateKey.from_private_bytes(bytes(reversed(range(32))))
    wrong_public = other_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    assert not CheckpointSigner.verify_checkpoint(
        signed.as_dict(), base64.b64encode(wrong_public).decode()
    )
    with pytest.raises(ValueError, match="exactly the required fields"):
        CheckpointSigner.verify_checkpoint(
            {**signed.as_dict(), "unexpected": True}, str(fixture["publicKeyBase64"])
        )
    with pytest.raises(ValueError, match="sequence"):
        signer.sign_checkpoint(
            ledger_id="ledger", seq=True, chain_hash="0" * 64, created_at="now"
        )
    assert not CheckpointSigner.verify_checkpoint(
        {**signed.as_dict(), "ledgerId": "tampered"}, str(fixture["publicKeyBase64"])
    )


def test_key_material_requires_pkcs8_ed25519_and_matching_raw_public_key(
    fixture: dict[str, object],
) -> None:
    with pytest.raises(SigningKeyError, match="PKCS#8"):
        CheckpointSigner.from_pem(b"not a key", str(fixture["publicKeyBase64"]))
    rsa_pem = generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    with pytest.raises(SigningKeyError, match="Ed25519"):
        CheckpointSigner.from_pem(rsa_pem, str(fixture["publicKeyBase64"]))
    for invalid_public in (
        "not base64!",
        "A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg",
        base64.b64encode(b"short").decode(),
    ):
        with pytest.raises(SigningKeyError, match="Base64|32 bytes"):
            CheckpointSigner.from_pem(
                str(fixture["privateKeyPkcs8Pem"]).encode(), invalid_public
            )
    wrong_public = Ed25519PrivateKey.from_private_bytes(bytes(reversed(range(32))))
    wrong_public_b64 = base64.b64encode(
        wrong_public.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
    ).decode()
    with pytest.raises(SigningKeyError, match="do not match"):
        CheckpointSigner.from_pem(
            str(fixture["privateKeyPkcs8Pem"]).encode(), wrong_public_b64
        )
    with pytest.raises(ValueError, match="sequence"):
        CheckpointSigner.from_pem(
            str(fixture["privateKeyPkcs8Pem"]).encode(), str(fixture["publicKeyBase64"])
        ).sign_checkpoint(
            ledger_id="ledger",
            seq=9_007_199_254_740_992,
            chain_hash="0" * 64,
            created_at="now",
        )


def test_development_key_creation_is_exclusive_and_reusable(tmp_path: Path) -> None:
    private_path = tmp_path / "signing-private.pem"
    public_path = tmp_path / "signing-public.b64"
    first = CheckpointSigner.from_files(private_path, public_path, environment="dev")
    private_bytes = private_path.read_bytes()
    second = CheckpointSigner.from_files(private_path, public_path, environment="dev")
    assert first.key_id == second.key_id
    assert private_path.read_bytes() == private_bytes
    with pytest.raises(SigningKeyError, match="Environment"):
        CheckpointSigner.from_files(private_path, public_path, environment="test")
    if os.name != "nt":
        assert private_path.stat().st_mode & 0o777 == 0o600
        assert public_path.stat().st_mode & 0o777 == 0o600


def test_production_refuses_missing_and_partial_key_files(tmp_path: Path) -> None:
    private_path = tmp_path / "signing-private.pem"
    public_path = tmp_path / "signing-public.b64"
    with pytest.raises(SigningKeyError, match="Production"):
        CheckpointSigner.from_files(private_path, public_path, environment="prod")
    CheckpointSigner.from_files(private_path, public_path, environment="dev")
    public_path.unlink()
    with pytest.raises(SigningKeyError, match="Both signing key files"):
        CheckpointSigner.from_files(private_path, public_path, environment="dev")
