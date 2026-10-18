from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType

import pytest
from e2e_support import JAR, java_available

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "benchmark.py"


def load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("benchmark_script", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_percentile_uses_nearest_rank() -> None:
    module = load()
    values = [float(n) for n in range(1, 101)]
    assert module.percentile(values, 50) == 50.0
    assert module.percentile(values, 95) == 95.0
    assert module.percentile(values, 99) == 99.0
    assert module.percentile([7.0], 99) == 7.0
    assert module.percentile([1.0, 2.0], 50) == 1.0


def test_summarize_handles_empty_and_orders_values() -> None:
    module = load()
    assert module.summarize([]) is None
    summary = module.summarize([5.0, 1.0, 3.0])
    assert (summary["min"], summary["p50"], summary["max"]) == (1.0, 3.0, 5.0)


def test_parse_int_list_rejects_bad_input() -> None:
    module = load()
    assert module.parse_int_list("1, 4,8") == [1, 4, 8]
    for bad in ("", "0", "-1", "a"):
        with pytest.raises(ValueError):
            module.parse_int_list(bad)


@pytest.mark.parametrize(
    "extra",
    [
        ["--events", "0"],
        ["--concurrency", "0"],
        ["--services", "ruby"],
        ["--payload-leaves", "501"],
        ["--payload-leaves", "400", "--payload-bytes", "200"],
        ["--query-limit", "501"],
        ["--warmup", "-1"],
    ],
)
def test_invalid_workloads_are_usage_errors(extra: list[str]) -> None:
    module = load()
    assert module.main([*extra, "--jar", str(SCRIPT)]) == 2


def test_missing_jar_is_a_usage_error(tmp_path: Path) -> None:
    module = load()
    assert module.main(["--services", "java", "--jar", str(tmp_path / "nope.jar")]) == 2


@pytest.mark.e2e
@pytest.mark.parametrize("kind", ["python", "java"])
def test_tiny_benchmark_runs_end_to_end_and_reports_shape(
    kind: str, tmp_path: Path
) -> None:
    """Smoke only: checks the run completes and the report shape. No timing gate."""
    if kind == "java" and not (java_available() and JAR.is_file()):
        pytest.skip("Java service jar not built")
    module = load()
    output = tmp_path / "result.json"
    exit_code = module.main(
        [
            "--services", kind,
            "--events", "12",
            "--warmup", "4",
            "--concurrency", "1,2",
            "--queries", "6",
            "--scan-pages", "2",
            "--verify-runs", "1",
            "--export-runs", "1",
            "--export-set-runs", "1",
            "--fsync-iterations", "5",
            "--work-dir", str(tmp_path / "work"),
            "--output", str(output),
        ]
    )  # fmt: skip
    assert exit_code == 0
    report = json.loads(output.read_text())
    assert report["environment"]["os"] and report["fsyncProbe"]["latencyMs"]
    result = report["results"][0]
    assert result["functionalErrors"] == []
    for level in result["append"]["levels"]:
        assert level["okRequests"] == 12 and level["latencyMs"]["p99"] >= 0
    assert all(run["intact"] for run in result["verify"]["runs"])
    assert result["export"]["exportSet"]["runs"][0]["finalStatus"] == "READY"
