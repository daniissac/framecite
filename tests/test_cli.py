from __future__ import annotations

import subprocess
import sys


def test_cli_help_documents_required_root() -> None:
    completed = subprocess.run(
        [sys.executable, "-m", "framecite", "--help"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0
    assert "--root" in completed.stdout
    assert "stdio" in completed.stdout


def test_cli_refuses_to_start_without_root() -> None:
    completed = subprocess.run(
        [sys.executable, "-m", "framecite"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 2
    assert "--root" in completed.stderr
