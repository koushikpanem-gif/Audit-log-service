import subprocess
import sys
from pathlib import Path

GENERATOR = Path(__file__).parent / "fixtures" / "generate_bundle_vectors.py"


def test_frozen_bundle_fixtures_match_generator() -> None:
    result = subprocess.run(
        [sys.executable, str(GENERATOR), "--check"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
