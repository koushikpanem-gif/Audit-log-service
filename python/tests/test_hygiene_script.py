from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "check_hygiene.py"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("check_hygiene", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def hygiene(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    module = _load()
    monkeypatch.setattr(module, "ROOT", tmp_path)
    return module


def _track(module: ModuleType, monkeypatch: pytest.MonkeyPatch, *names: str) -> None:
    monkeypatch.setattr(module, "tracked_files", lambda: list(names))


def test_flags_private_keys_databases_and_tokens(
    hygiene: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "leak.txt").write_text(
        "-----BEGIN PRIVATE KEY-----\n" + "A" * 64 + "\n-----END PRIVATE KEY-----\n"
    )
    (tmp_path / "audit.db").write_bytes(b"SQLite format 3")
    # Built in pieces so this fixture does not itself match the scanner's pattern.
    fake = "abcdefghijklmnopqrstuvwxyz0123"
    (tmp_path / "notes.md").write_text('api_key = "' + fake + '"')
    _track(hygiene, monkeypatch, "leak.txt", "audit.db", "notes.md")
    findings = hygiene.scan()
    assert len(findings) == 3
    assert any("private key" in item for item in findings)
    assert any("audit.db" in item for item in findings)
    assert any("secret assignment" in item for item in findings)


def test_clean_files_and_allowlisted_test_key_pass(
    hygiene: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "ok.md").write_text("The api key is supplied via a hashed file.")
    vector = tmp_path / "docs" / "test-vectors"
    vector.mkdir(parents=True)
    (vector / "ed25519-checkpoint-v1.json").write_text(
        "-----BEGIN PRIVATE KEY-----\n" + "A" * 64 + "\n-----END PRIVATE KEY-----\n"
    )
    _track(
        hygiene,
        monkeypatch,
        "ok.md",
        "docs/test-vectors/ed25519-checkpoint-v1.json",
    )
    assert hygiene.scan() == []
