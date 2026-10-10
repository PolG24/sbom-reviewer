"""Behavioral tests for the installed command-line interface."""

import subprocess


def test_help_describes_the_application() -> None:
    result = subprocess.run(
        ["sbom-reviewer", "--help"],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert "Review Software Bills of Materials" in result.stdout
    assert "usage: sbom-reviewer" in result.stdout
