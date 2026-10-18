"""Tests for the independent offline verifier.

Java-signed fixtures are frozen output of the Java service (PythonInteropTests);
Python-signed fixtures come from generate_verifier_vectors.py. Re-signing helpers use
the public RFC 8032 test key only.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import io
import json
import os
import re
import shutil
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from audit_log_service.verifier import (
    INVALID,
    UNTRUSTED,
    VERIFIED,
    InputError,
    Options,
    cli,
    verify_bundle,
    verify_export_set,
)
from audit_log_service.verifier.jcs import (
    JsonError,
    canonicalize,
    format_double,
    parse_strict,
)

FIXTURES = Path(__file__).parent / "fixtures"
VECTORS = FIXTURES / "bundle_vectors"
DOCS_VECTORS = Path(__file__).parents[2] / "docs" / "test-vectors" / "jcs-v1.json"
PUBLIC = (VECTORS / "test_key_public.b64").read_text().strip()
KEY = serialization.load_pem_private_key(
    (VECTORS / "test_key_private.pem").read_bytes(), None
)
assert isinstance(KEY, Ed25519PrivateKey)
PINNED = Options(pinned_key=PUBLIC)

BUNDLES = {
    "java": FIXTURES / "java_signed" / "bundle.json",
    "python": FIXTURES / "python_signed" / "bundle.json",
    "gapped": VECTORS / "gapped.json",
    "partial": VECTORS / "partial.json",
    "empty": VECTORS / "empty.json",
}
SETS = {
    "java": FIXTURES / "java_signed" / "export_set",
    "python": FIXTURES / "python_signed" / "export_set",
}


def codes(result: Any) -> set[str]:
    return {item["code"] for item in result.diagnostics}


def sign_body(body: dict[str, Any]) -> dict[str, Any]:
    body.pop("signature", None)
    body["signature"] = base64.b64encode(KEY.sign(canonicalize(body))).decode()
    return body


def load(name: str) -> dict[str, Any]:
    loaded: dict[str, Any] = json.loads(BUNDLES[name].read_text(encoding="utf-8"))
    return loaded


def verify_dict(body: dict[str, Any], options: Options = PINNED) -> Any:
    return verify_bundle(json.dumps(body).encode(), options)


# ---- canonicalization and strict parsing ----


def test_shared_jcs_vectors() -> None:
    vectors = json.loads(DOCS_VECTORS.read_text(encoding="utf-8"))
    for case in vectors["canonicalization"]:
        got = canonicalize(parse_strict(case["input"].encode()))
        assert got.decode() == case["expected"], case["name"]


@pytest.mark.parametrize(
    ("value", "text"),
    [
        (0.1, "0.1"),
        (1e21, "1e+21"),
        (1e-7, "1e-7"),
        (123456789012345680000.0, "123456789012345680000"),
        (-0.0, "0"),
        (5e-324, "5e-324"),
        (1.7976931348623157e308, "1.7976931348623157e+308"),
        (100.0, "100"),
        (0.000001, "0.000001"),
    ],
)
def test_double_formatting(value: float, text: str) -> None:
    assert format_double(value) == text


def test_matches_service_canonicalizer_on_mixed_document() -> None:
    from audit_log_service.canonical_json import canonicalize as service

    document = {
        "z": [1, 2.5, None, True, "Ã©\u2028\U0001d11e"],
        "\ue000": {},
        "\U00010000": [],
        "a": -0.0,
    }
    assert canonicalize(document) == service(document)


@pytest.mark.parametrize(
    "raw",
    [
        b'{"a":1,"a":2}',
        b'{"a":9007199254740992}',
        b'{"a":NaN}',
        b'{"a":Infinity}',
        b'{"a":"\\ud800"}',
        b"\xef\xbb\xbf{}",
        b"\xff",
        b'{"a":1} x',
        b'{"a":1e999}',
    ],
)
def test_parse_strict_rejects(raw: bytes) -> None:
    with pytest.raises(JsonError):
        parse_strict(raw)


def test_parse_depth_is_iterative() -> None:
    with pytest.raises(JsonError):
        parse_strict(b"[" * 100000 + b"]" * 100000)


# ---- fixtures from both directions ----


@pytest.mark.parametrize("name", list(BUNDLES))
def test_all_fixture_bundles_verify_pinned(name: str) -> None:
    result = verify_bundle(BUNDLES[name].read_bytes(), PINNED)
    assert result.status == VERIFIED, result.diagnostics
    assert result.origin_trusted


def test_redaction_and_gaps_are_counted_not_invented() -> None:
    assert (
        verify_bundle(BUNDLES["python"].read_bytes(), PINNED).undisclosed_leaf_count
        == 1
    )
    assert (
        verify_bundle(BUNDLES["partial"].read_bytes(), PINNED).undisclosed_leaf_count
        == 1
    )
    gapped = verify_bundle(BUNDLES["gapped"].read_bytes(), PINNED)
    assert gapped.record_count == 2 and gapped.undisclosed_leaf_count == 0


@pytest.mark.parametrize("name", list(SETS))
def test_export_sets_verify_pinned(name: str) -> None:
    result = verify_export_set(SETS[name] / "manifest.json", PINNED)
    assert result.status == VERIFIED, result.diagnostics


def test_java_fixture_covers_unicode_doubles_nulls_empties() -> None:
    first = load("java")["records"][0]
    assert first["payloadCommitments"]["nothing"]
    assert first["payloadCommitments"]["emptyObject"] == {}
    assert first["payloadCommitments"]["emptyArray"] == []
    assert first["disclosedLeaves"]["/double"]["value"] == 0.1
    assert first["disclosedLeaves"]["/big"]["value"] == 1e21
    assert "\U0001d11e" in first["disclosedLeaves"]["/text"]["value"]


# ---- trust and pinning ----


def test_trust_modes() -> None:
    raw = BUNDLES["java"].read_bytes()
    unconfigured = verify_bundle(raw)
    assert unconfigured.status == INVALID and "TRUSTED_KEY_REQUIRED" in codes(
        unconfigured
    )
    self_asserted = verify_bundle(raw, Options(allow_self_asserted=True))
    assert self_asserted.status == UNTRUSTED and not self_asserted.origin_trusted
    assert any("UNTRUSTED ORIGIN" in n for n in self_asserted.notices)


def test_wrong_pinned_key_is_rejected() -> None:
    other = (
        Ed25519PrivateKey.generate()
        .public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    )
    result = verify_bundle(
        BUNDLES["java"].read_bytes(),
        Options(pinned_key=base64.b64encode(other).decode()),
    )
    assert result.status == INVALID and "SIGNER_KEY_MISMATCH" in codes(result)


def test_der_encoded_pinned_key_is_an_input_error() -> None:
    der = KEY.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    assert len(der) == 44
    with pytest.raises(InputError):
        verify_bundle(b"{}", Options(pinned_key=base64.b64encode(der).decode()))


def test_der_key_embedded_in_bundle_is_rejected_even_when_resigned() -> None:
    body = load("java")
    der = KEY.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    body["signer"]["publicKey"] = base64.b64encode(der).decode()
    result = verify_dict(sign_body(body), Options(allow_self_asserted=True))
    assert result.status == INVALID and "BUNDLE_SCHEMA_INVALID" in codes(result)


def test_pinned_key_and_self_asserted_conflict() -> None:
    with pytest.raises(InputError):
        verify_bundle(b"{}", Options(pinned_key=PUBLIC, allow_self_asserted=True))


def test_non_canonical_base64_pin_rejected() -> None:
    with pytest.raises(InputError):
        verify_bundle(b"{}", Options(pinned_key=PUBLIC.rstrip("=")))


# ---- tampering ----


def test_unsigned_mutation_breaks_signature() -> None:
    body = load("java")
    body["records"][0]["eventType"] = "FORGED"
    assert "BUNDLE_SIGNATURE_INVALID" in codes(verify_dict(body))


def test_resigned_mutations_report_precise_codes() -> None:
    cases: list[tuple[str, Any, str]] = [
        (
            "content",
            lambda b: b["records"][0].__setitem__("eventType", "X"),
            "CONTENT_HASH_MISMATCH",
        ),
        (
            "chain",
            lambda b: b["records"][0].__setitem__("chainHash", "0" * 64),
            "CHAIN_HASH_MISMATCH",
        ),
        (
            "genesis",
            lambda b: b.__setitem__("genesisHash", "1" * 64),
            "GENESIS_MISMATCH",
        ),
        ("count", lambda b: b.__setitem__("recordCount", 5), "RECORD_COUNT_MISMATCH"),
        (
            "digest",
            lambda b: b.__setitem__("recordsDigest", "2" * 64),
            "RECORDS_DIGEST_MISMATCH",
        ),
        ("order", lambda b: b["records"].reverse(), "RECORD_ORDER_INVALID"),
        (
            "leaf",
            lambda b: b["records"][0]["disclosedLeaves"]["/double"].__setitem__(
                "value", 0.2
            ),
            "LEAF_COMMITMENT_MISMATCH",
        ),
        (
            "selection",
            lambda b: b["selection"].__setitem__("actorId", "bob"),
            "SELECTION_MISMATCH",
        ),
        (
            "algorithm",
            lambda b: b.__setitem__("hashAlgorithm", "SHA-1"),
            "UNSUPPORTED_ALGORITHM",
        ),
        (
            "format",
            lambda b: b.__setitem__("format", "audit-export-bundle/v2"),
            "UNSUPPORTED_FORMAT",
        ),
    ]
    for label, mutate, code in cases:
        body = load("python")
        mutate(body)
        if label in {"count", "digest", "order", "selection"}:
            body["recordsDigest"] = (
                body["recordsDigest"]
                if label == "digest"
                else hashlib.sha256(canonicalize(body["records"])).hexdigest()
            )
        result = verify_dict(sign_body(body))
        assert code in codes(result), (label, result.diagnostics)
        assert result.status == INVALID


def test_checkpoint_signed_by_other_key_is_detected() -> None:
    body = load("python")
    body["headCheckpoint"]["signature"] = base64.b64encode(b"\x01" * 64).decode()
    assert "CHECKPOINT_SIGNATURE_INVALID" in codes(verify_dict(sign_body(body)))


def test_extra_and_missing_fields_rejected() -> None:
    body = load("python")
    body["extra"] = 1
    assert "BUNDLE_SCHEMA_INVALID" in codes(verify_dict(sign_body(body)))
    body = load("python")
    del body["records"][0]["source"]
    assert "BUNDLE_SCHEMA_INVALID" in codes(verify_dict(sign_body(body)))


def test_chain_break_between_adjacent_records() -> None:
    import sys

    from audit_log_service.v1_hashes import chain_hash

    sys.path.insert(0, str(FIXTURES))
    from generate_verifier_vectors import build_ledger

    ledger = build_ledger()
    body = load("python")
    first, second = (copy.deepcopy(e) for e in ledger.events[:2])
    second["prevHash"] = "f" * 64
    second["chainHash"] = chain_hash(second["prevHash"], second["contentHash"])
    body["records"] = [first, second]
    body["recordCount"] = 2
    body["recordsDigest"] = hashlib.sha256(canonicalize(body["records"])).hexdigest()
    body["selection"]["actorId"] = None
    body["selection"]["resourceType"] = "DOC"
    body["selection"]["resourceId"] = "d1"
    result = verify_dict(sign_body(body))
    assert "CHAIN_LINK_BROKEN" in codes(result)
    assert "CHAIN_HASH_MISMATCH" not in codes(result)


def test_resource_limits_and_malformed_inputs() -> None:
    raw = BUNDLES["java"].read_bytes()
    assert "RESOURCE_LIMIT_EXCEEDED" in codes(
        verify_bundle(raw, Options(pinned_key=PUBLIC, max_bytes=100))
    )
    assert "RESOURCE_LIMIT_EXCEEDED" in codes(
        verify_bundle(raw, Options(pinned_key=PUBLIC, max_records=1))
    )
    assert "BUNDLE_SCHEMA_INVALID" in codes(verify_bundle(b"", PINNED))
    assert "BUNDLE_SCHEMA_INVALID" in codes(verify_bundle(b"[]", PINNED))
    assert "BUNDLE_SCHEMA_INVALID" in codes(verify_bundle(b'{"a":1,"a":2}', PINNED))
    assert "RESOURCE_LIMIT_EXCEEDED" in codes(
        verify_bundle(b"[" * 40 + b"]" * 40, PINNED)
    )


def test_diagnostics_are_capped_with_exact_total() -> None:
    body = load("java")
    template = body["records"][0]
    body["records"] = [dict(template, seq=template["seq"] + i) for i in range(120)]
    body["recordCount"] = 120
    body["recordsDigest"] = hashlib.sha256(canonicalize(body["records"])).hexdigest()
    result = verify_dict(sign_body(body))
    assert len(result.diagnostics) == 100
    assert result.total_diagnostic_count > 100 and result.diagnostics_truncated


# ---- export sets ----


@pytest.fixture
def set_copy(tmp_path: Path) -> Path:
    target = tmp_path / "set"
    shutil.copytree(SETS["python"], target)
    return target


def resign_manifest(directory: Path, change: Any) -> None:
    path = directory / "manifest.json"
    manifest = json.loads(path.read_text(encoding="utf-8"))
    change(manifest)
    manifest["chunksDigest"] = hashlib.sha256(
        canonicalize(manifest["chunks"])
    ).hexdigest()
    path.write_bytes(canonicalize(sign_body(manifest)))


def test_altered_chunk_detected(set_copy: Path) -> None:
    chunk = set_copy / "chunk-000000.json"
    chunk.write_bytes(chunk.read_bytes().replace(b"alice", b"mallo"))
    result = verify_export_set(set_copy / "manifest.json", PINNED)
    assert "CHUNK_DIGEST_MISMATCH" in codes(result)


def test_missing_chunk_detected(set_copy: Path) -> None:
    (set_copy / "chunk-000001.json").unlink()
    assert "CHUNK_MISSING" in codes(
        verify_export_set(set_copy / "manifest.json", PINNED)
    )


def test_unlisted_chunk_detected(set_copy: Path) -> None:
    shutil.copy(set_copy / "chunk-000001.json", set_copy / "chunk-000009.json")
    assert "CHUNK_UNEXPECTED" in codes(
        verify_export_set(set_copy / "manifest.json", PINNED)
    )


def test_dropped_chunk_in_signed_manifest_detected(set_copy: Path) -> None:
    resign_manifest(set_copy, lambda m: (m["chunks"].pop(), m.update(chunkCount=1)))
    result = verify_export_set(set_copy / "manifest.json", PINNED)
    assert {"TOTAL_COUNT_MISMATCH", "CHUNK_UNEXPECTED"} <= codes(result)


def test_unsafe_chunk_names_rejected(set_copy: Path) -> None:
    for bad in (
        "../chunk-000000.json",
        "chunk-0.json",
        "C:\\x\\chunk-000000.json",
        "/etc/passwd",
    ):
        resign_manifest(
            set_copy, lambda m, bad=bad: m["chunks"][0].__setitem__("name", bad)
        )
        assert "CHUNK_NAME_UNSAFE" in codes(
            verify_export_set(set_copy / "manifest.json", PINNED)
        ), bad


def test_chunk_order_and_set_identity(set_copy: Path) -> None:
    resign_manifest(set_copy, lambda m: m["chunks"].reverse())
    assert "CHUNK_ORDER_INVALID" in codes(
        verify_export_set(set_copy / "manifest.json", PINNED)
    )


def test_chunk_from_other_set_detected(set_copy: Path) -> None:
    resign_manifest(set_copy, lambda m: m.__setitem__("exportSetId", "other"))
    assert "CHUNK_ORDER_INVALID" in codes(
        verify_export_set(set_copy / "manifest.json", PINNED)
    )


def test_manifest_wrong_key_and_tamper(set_copy: Path) -> None:
    other = base64.b64encode(
        Ed25519PrivateKey.generate()
        .public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    ).decode()
    assert "SIGNER_KEY_MISMATCH" in codes(
        verify_export_set(set_copy / "manifest.json", Options(pinned_key=other))
    )
    path = set_copy / "manifest.json"
    path.write_bytes(path.read_bytes().replace(b"interop-auditor", b"someone-else"))
    assert "BUNDLE_SIGNATURE_INVALID" in codes(verify_export_set(path, PINNED))


def test_declared_size_limit_and_oversized_chunk(set_copy: Path) -> None:
    result = verify_export_set(
        set_copy / "manifest.json", Options(pinned_key=PUBLIC, max_bytes=2000)
    )
    assert "RESOURCE_LIMIT_EXCEEDED" in codes(result)
    chunk = set_copy / "chunk-000001.json"
    chunk.write_bytes(chunk.read_bytes() + b" ")
    assert "CHUNK_DIGEST_MISMATCH" in codes(
        verify_export_set(set_copy / "manifest.json", PINNED)
    )


def test_symlinked_chunk_is_not_followed(set_copy: Path, tmp_path: Path) -> None:
    outside = tmp_path / "outside.json"
    shutil.copy(set_copy / "chunk-000001.json", outside)
    (set_copy / "chunk-000001.json").unlink()
    try:
        os.symlink(outside, set_copy / "chunk-000001.json")
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable on this platform")
    assert "CHUNK_MISSING" in codes(
        verify_export_set(set_copy / "manifest.json", PINNED)
    )


# ---- CLI ----


def run_cli(*args: str) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    return cli.run(list(args), out, err), out.getvalue(), err.getvalue()


def test_cli_exit_codes(tmp_path: Path) -> None:
    key = str(VECTORS / "test_key_public.b64")
    bundle = str(BUNDLES["java"])
    code, out, _ = run_cli("--bundle", bundle, "--pinned-key-file", key)
    assert code == 0 and out.startswith("VERIFIED")
    code, out, _ = run_cli("--bundle", bundle, "--allow-self-asserted")
    assert (
        code == 0
        and out.startswith("INTEGRITY_VALID_ORIGIN_UNTRUSTED")
        and "WARNING" in out
    )
    assert not out.startswith("VERIFIED")
    assert run_cli("--bundle", bundle)[0] == 1
    tampered = tmp_path / "t.json"
    tampered.write_bytes(BUNDLES["java"].read_bytes().replace(b"alice", b"mallo"))
    assert run_cli("--bundle", str(tampered), "--pinned-key", PUBLIC)[0] == 1
    manifest = str(SETS["java"] / "manifest.json")
    assert run_cli("--manifest", manifest, "--pinned-key", PUBLIC)[0] == 0


@pytest.mark.parametrize(
    "args",
    [
        [],
        ["--bundle", "a", "--manifest", "b"],
        ["--bundle", "missing.json", "--pinned-key", PUBLIC],
        ["--bundle", str(BUNDLES["java"]), "--pinned-key", "!!"],
        [
            "--bundle",
            str(BUNDLES["java"]),
            "--pinned-key",
            PUBLIC,
            "--allow-self-asserted",
        ],
        [
            "--bundle",
            str(BUNDLES["java"]),
            "--pinned-key",
            PUBLIC,
            "--pinned-key-file",
            "x",
        ],
        ["--bundle", str(BUNDLES["java"]), "--bogus"],
        ["--bundle", str(BUNDLES["java"]), "--max-bytes", "abc"],
        ["--manifest", "missing/manifest.json", "--pinned-key", PUBLIC],
    ],
)
def test_cli_usage_errors_exit_2(args: list[str]) -> None:
    code, out, err = run_cli(*args)
    assert code == 2 and not out and err.startswith("ERROR")


# ---- independence ----


def test_verifier_has_no_service_or_web_imports() -> None:
    package = Path(cli.__file__).parent
    pattern = re.compile(r"^\s*(?:from|import)\s+([\w.]+)", re.MULTILINE)
    for source in package.glob("*.py"):
        for module in pattern.findall(source.read_text(encoding="utf-8")):
            assert not module.startswith(
                ("starlette", "pydantic", "uvicorn", "rfc8785")
            ), source
            if module.startswith("audit_log_service"):
                assert module.startswith("audit_log_service.verifier"), (source, module)
            assert "java" not in module.lower(), source
