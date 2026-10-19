"""Provision production signing and API-key material for ONE service instance.

Creates, exclusively (never overwriting), in --output-dir:
  signing-private.pem  PKCS#8 PEM Ed25519 private key (owner-only on POSIX)
  signing-public.b64   Base64 of the raw 32-byte public key
  api-keys.json        principal -> {keyHash, roles}; hashes only

Plaintext API keys are printed ONCE to stdout and never written to disk. Run it
once per deployment.
Requires only the `cryptography` package. Exit: 0 ok, 2 usage/refused.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import secrets
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROLES = ("writer", "reader", "auditor", "admin")


def _write_exclusive(path: Path, data: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())


def provision(output_dir: Path, principals: dict[str, str]) -> dict[str, str]:
    output_dir.mkdir(parents=True, exist_ok=True)
    targets = [
        output_dir / "signing-private.pem",
        output_dir / "signing-public.b64",
        output_dir / "api-keys.json",
    ]
    existing = [target.name for target in targets if target.exists()]
    if existing:
        raise FileExistsError(f"refusing to overwrite existing files: {existing}")
    private = Ed25519PrivateKey.generate()
    pem = private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    raw_public = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    issued: dict[str, str] = {}
    document: dict[str, dict[str, object]] = {}
    for name, role in principals.items():
        credential = secrets.token_urlsafe(32)
        issued[name] = credential
        document[name] = {
            "keyHash": hashlib.sha256(credential.encode("utf-8")).hexdigest(),
            "roles": [role],
        }
    _write_exclusive(targets[0], pem)
    _write_exclusive(targets[1], base64.b64encode(raw_public))
    _write_exclusive(targets[2], json.dumps(document, indent=2).encode("utf-8"))
    return issued


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument(
        "--principal",
        action="append",
        default=[],
        metavar="NAME=ROLE",
        help="repeatable; ROLE is one of " + ", ".join(ROLES),
    )
    args = parser.parse_args(argv)
    principals: dict[str, str] = {}
    for item in args.principal or ["writer=writer", "reader=reader", "auditor=auditor", "admin=admin"]:
        name, _, role = item.partition("=")
        if not name or role not in ROLES or name in principals:
            print(f"invalid or duplicate principal: {item!r}", file=sys.stderr)
            return 2
        principals[name] = role
    try:
        issued = provision(args.output_dir, principals)
    except (FileExistsError, OSError) as error:
        print(f"provisioning refused: {error}", file=sys.stderr)
        return 2
    print(f"Wrote key material to {args.output_dir} (private key is secret).")
    print("API keys are shown once; store them in your secret manager:")
    for name, credential in issued.items():
        print(f"  {name}: {credential}")
    if os.name == "nt":
        print("Windows: restrict the output directory ACL to the service account.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
