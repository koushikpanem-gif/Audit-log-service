from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from audit_log_service.canonical_json import MAX_SAFE_INTEGER, JsonValue, canonicalize

_KEY_ID_LENGTH = 16
_CHECKPOINT_TYPE = "audit-checkpoint/v1"
_ED25519_RAW_KEY_LENGTH = 32


class SigningKeyError(ValueError):
    """Raised when signing key material is invalid or unsafe to load."""


@dataclass(frozen=True)
class Checkpoint:
    message: dict[str, JsonValue]
    key_id: str
    signature: str

    def as_dict(self) -> dict[str, JsonValue]:
        return {
            **self.message,
            "keyId": self.key_id,
            "signature": self.signature,
        }


class CheckpointSigner:
    def __init__(
        self,
        private_key: Ed25519PrivateKey,
        public_key: Ed25519PublicKey,
    ) -> None:
        private_raw = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        public_raw = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        if not hmac.compare_digest(private_raw, public_raw):
            raise SigningKeyError("Private and public Ed25519 keys do not match")
        self._private_key = private_key
        self._public_key = public_key
        self._public_raw = public_raw
        self._key_id = hashlib.sha256(public_raw).hexdigest()[:_KEY_ID_LENGTH]

    @classmethod
    def from_pem(cls, private_pem: bytes, public_key_base64: str) -> CheckpointSigner:
        if not isinstance(private_pem, bytes):
            raise SigningKeyError("Private key must be PKCS#8 PEM bytes")
        if not private_pem.startswith(
            b"-----BEGIN PRIVATE KEY-----"
        ) or not private_pem.rstrip().endswith(b"-----END PRIVATE KEY-----"):
            raise SigningKeyError("Private key must be unencrypted PKCS#8 PEM")
        try:
            private_key = serialization.load_pem_private_key(private_pem, password=None)
        except (TypeError, ValueError) as exc:
            raise SigningKeyError(
                "Private key must be valid unencrypted PKCS#8 PEM"
            ) from exc
        if not isinstance(private_key, Ed25519PrivateKey):
            raise SigningKeyError("Private key must use Ed25519")
        if not isinstance(public_key_base64, str):
            raise SigningKeyError("Public key must be Base64 text")
        try:
            public_raw = base64.b64decode(public_key_base64, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise SigningKeyError("Public key must be valid Base64") from exc
        if base64.b64encode(public_raw).decode("ascii") != public_key_base64:
            raise SigningKeyError("Public key must use canonical standard Base64")
        if len(public_raw) != _ED25519_RAW_KEY_LENGTH:
            raise SigningKeyError(
                "Raw Ed25519 public key must contain exactly 32 bytes"
            )
        try:
            public_key = Ed25519PublicKey.from_public_bytes(public_raw)
        except ValueError as exc:
            raise SigningKeyError("Raw Ed25519 public key is invalid") from exc
        return cls(private_key, public_key)

    @classmethod
    def from_files(
        cls,
        private_path: Path,
        public_path: Path,
        *,
        environment: str,
    ) -> CheckpointSigner:
        if environment not in {"dev", "prod"}:
            raise SigningKeyError("Environment must be 'dev' or 'prod'")
        if private_path.exists() or public_path.exists():
            if not private_path.is_file() or not public_path.is_file():
                raise SigningKeyError(
                    "Both signing key files must exist and be regular files"
                )
            try:
                with private_path.open("rb") as private_file:
                    private_pem = private_file.read(16 * 1024 + 1)
                with public_path.open("rb") as public_file:
                    public_bytes = public_file.read(129)
                if len(private_pem) > 16 * 1024 or len(public_bytes) > 128:
                    raise SigningKeyError("Signing key file exceeds its size limit")
                return cls.from_pem(
                    private_pem,
                    public_bytes.decode("ascii").strip(),
                )
            except (OSError, UnicodeDecodeError) as exc:
                raise SigningKeyError("Unable to read signing key files") from exc
        if environment == "prod":
            raise SigningKeyError("Production requires existing signing key files")
        if private_path.resolve() == public_path.resolve():
            raise SigningKeyError(
                "Private and public key files must be different paths"
            )
        private_key = Ed25519PrivateKey.generate()
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_raw = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        private_path.parent.mkdir(parents=True, exist_ok=True)
        public_path.parent.mkdir(parents=True, exist_ok=True)
        _create_private_file(private_path, private_pem)
        try:
            _create_private_file(public_path, base64.b64encode(public_raw) + b"\n")
        except OSError:
            private_path.unlink(missing_ok=True)
            raise
        return cls.from_pem(private_pem, base64.b64encode(public_raw).decode("ascii"))

    @property
    def public_key_base64(self) -> str:
        return base64.b64encode(self._public_raw).decode("ascii")

    @property
    def key_id(self) -> str:
        return self._key_id

    def sign_checkpoint(
        self,
        *,
        ledger_id: str,
        seq: int,
        chain_hash: str,
        created_at: str,
    ) -> Checkpoint:
        if type(seq) is not int or not 1 <= seq <= MAX_SAFE_INTEGER:
            raise ValueError("Checkpoint sequence must be a positive safe integer")
        if not isinstance(ledger_id, str) or not ledger_id.strip():
            raise ValueError("Checkpoint ledgerId must be non-empty text")
        try:
            ledger_id_length = len(ledger_id.encode("utf-8", errors="strict"))
        except UnicodeEncodeError as exc:
            raise ValueError("Checkpoint ledgerId must contain valid Unicode") from exc
        if ledger_id_length > 256:
            raise ValueError("Checkpoint ledgerId exceeds 256 UTF-8 bytes")
        if (
            not isinstance(chain_hash, str)
            or len(chain_hash) != 64
            or any(char not in "0123456789abcdef" for char in chain_hash)
            or not isinstance(created_at, str)
            or not created_at.strip()
        ):
            raise ValueError("Checkpoint message fields are invalid")
        message: dict[str, JsonValue] = {
            "type": _CHECKPOINT_TYPE,
            "ledgerId": ledger_id,
            "seq": seq,
            "chainHash": chain_hash,
            "createdAt": created_at,
        }
        signature = self._private_key.sign(canonicalize(message))
        return Checkpoint(
            message=message,
            key_id=self._key_id,
            signature=base64.b64encode(signature).decode("ascii"),
        )

    @staticmethod
    def verify_checkpoint(
        checkpoint: dict[str, object],
        public_key_base64: str,
    ) -> bool:
        if not isinstance(checkpoint, dict):
            raise ValueError("Checkpoint must be an object")
        expected_fields = {
            "type",
            "ledgerId",
            "seq",
            "chainHash",
            "createdAt",
            "keyId",
            "signature",
        }
        if set(checkpoint) != expected_fields:
            raise ValueError("Checkpoint must have exactly the required fields")
        key_id = checkpoint["keyId"]
        signature = checkpoint["signature"]
        checkpoint_type = checkpoint["type"]
        ledger_id = checkpoint["ledgerId"]
        seq = checkpoint["seq"]
        chain_hash = checkpoint["chainHash"]
        created_at = checkpoint["createdAt"]
        if (
            not isinstance(key_id, str)
            or not isinstance(signature, str)
            or not isinstance(checkpoint_type, str)
            or checkpoint_type != _CHECKPOINT_TYPE
            or not isinstance(ledger_id, str)
            or not ledger_id.strip()
            or type(seq) is not int
            or not 1 <= seq <= MAX_SAFE_INTEGER
            or not isinstance(chain_hash, str)
            or len(chain_hash) != 64
            or any(char not in "0123456789abcdef" for char in chain_hash)
            or not isinstance(created_at, str)
            or not created_at.strip()
        ):
            raise ValueError("Checkpoint message fields have invalid types")
        try:
            if len(ledger_id.encode("utf-8", errors="strict")) > 256:
                raise ValueError("Checkpoint ledgerId exceeds 256 UTF-8 bytes")
        except UnicodeEncodeError as exc:
            raise ValueError("Checkpoint ledgerId must contain valid Unicode") from exc
        public_raw = _decode_public_key(public_key_base64)
        expected_key_id = hashlib.sha256(public_raw).hexdigest()[:_KEY_ID_LENGTH]
        if not hmac.compare_digest(expected_key_id, key_id):
            return False
        message: dict[str, JsonValue] = {
            "type": checkpoint_type,
            "ledgerId": ledger_id,
            "seq": seq,
            "chainHash": chain_hash,
            "createdAt": created_at,
        }
        try:
            signature_bytes = base64.b64decode(signature, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise ValueError("Checkpoint signature must be valid Base64") from exc
        if base64.b64encode(signature_bytes).decode("ascii") != signature:
            raise ValueError("Checkpoint signature must use canonical standard Base64")
        try:
            Ed25519PublicKey.from_public_bytes(public_raw).verify(
                signature_bytes, canonicalize(message)
            )
            return True
        except InvalidSignature:
            return False


def _decode_public_key(public_key_base64: str) -> bytes:
    if not isinstance(public_key_base64, str):
        raise SigningKeyError("Public key must be Base64 text")
    try:
        public_raw = base64.b64decode(public_key_base64, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise SigningKeyError("Public key must be valid Base64") from exc
    if base64.b64encode(public_raw).decode("ascii") != public_key_base64:
        raise SigningKeyError("Public key must use canonical standard Base64")
    if len(public_raw) != _ED25519_RAW_KEY_LENGTH:
        raise SigningKeyError("Raw Ed25519 public key must contain exactly 32 bytes")
    return public_raw


def _create_private_file(path: Path, contents: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(path, flags, 0o600)
    try:
        if os.name == "nt":
            username = os.environ.get("USERNAME")
            if not username:
                raise OSError("Current Windows account is unavailable for key ACL")
            domain = os.environ.get("USERDOMAIN")
            account = f"{domain}\\{username}" if domain else username
            result = subprocess.run(
                ["icacls", str(path), "/inheritance:r", "/grant:r", f"{account}:F"],
                capture_output=True,
                check=False,
                text=True,
            )
            if result.returncode != 0:
                raise OSError("Unable to restrict Windows signing-key ACL")
        else:
            os.chmod(path, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            descriptor = -1
            output.write(contents)
            output.flush()
            os.fsync(output.fileno())
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
        path.unlink(missing_ok=True)
        raise
