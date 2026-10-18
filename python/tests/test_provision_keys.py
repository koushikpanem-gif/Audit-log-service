from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import ModuleType

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "provision_keys.py"


def load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("provision_keys", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_provision_writes_hashes_only_and_never_overwrites(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    module = load()
    assert module.main(["--output-dir", str(tmp_path), "--principal", "ops=admin"]) == 0
    out = capsys.readouterr().out
    credential = out.split("ops: ")[1].split()[0]
    document = (tmp_path / "api-keys.json").read_text()
    assert credential not in document
    assert json.loads(document)["ops"]["roles"] == ["admin"]
    assert "BEGIN PRIVATE KEY" in (tmp_path / "signing-private.pem").read_text()
    before = (tmp_path / "signing-private.pem").read_bytes()
    assert module.main(["--output-dir", str(tmp_path)]) == 2
    assert (tmp_path / "signing-private.pem").read_bytes() == before


def test_provision_rejects_unknown_roles_and_duplicates(tmp_path: Path) -> None:
    module = load()
    assert module.main(["--output-dir", str(tmp_path), "--principal", "a=root"]) == 2
    assert (
        module.main(
            [
                "--output-dir",
                str(tmp_path),
                "--principal",
                "a=admin",
                "--principal",
                "a=reader",
            ]
        )
        == 2
    )
    assert not (tmp_path / "signing-private.pem").exists()
