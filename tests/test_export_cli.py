"""Export is offline, deterministic, nonmutating, and refuses overwrites."""

from pathlib import Path
import sys

import pytest

from sbom_reviewer.models import ReviewResult
from sbom_reviewer.storage import save_review
from test_cli import run_cli


def test_exports_are_identical_and_leave_snapshot_bytes_unchanged(tmp_path: Path, machine_review: ReviewResult) -> None:
    database = tmp_path / "review.sqlite"
    save_review(database, machine_review)
    before = database.read_bytes()
    outputs = [tmp_path / "first.html", tmp_path / "second.html"]
    for output in outputs:
        result = run_cli("export", str(database), "--output", str(output))
        assert result.returncode == 0 and result.stdout == result.stderr == ""
        assert database.read_bytes() == before
        assert "Pending human review" in output.read_text(encoding="utf-8")
    assert outputs[0].read_bytes() == outputs[1].read_bytes()


@pytest.mark.parametrize("failure", ["existing", "directory", "missing_parent", "same_as_database"])
def test_export_write_errors_preserve_files_and_have_no_success_output(tmp_path: Path, machine_review: ReviewResult, failure: str) -> None:
    database = tmp_path / "review.sqlite"
    save_review(database, machine_review)
    before = database.read_bytes()
    output = tmp_path / "report.html"
    if failure == "existing":
        output.write_bytes(b"preserve")
    elif failure == "directory":
        output.mkdir()
    elif failure == "missing_parent":
        output = tmp_path / "missing" / "report.html"
    else:
        output = database
    result = run_cli("export", str(database), "--output", str(output))
    assert result.returncode == 2 and result.stdout == ""
    assert str(output) in result.stderr and "Traceback" not in result.stderr
    assert database.read_bytes() == before
    if failure == "existing":
        assert output.read_bytes() == b"preserve"


@pytest.mark.parametrize("failure", ["missing", "text", "directory", "unsupported"])
def test_invalid_database_does_not_create_report_or_database(tmp_path: Path, machine_review: ReviewResult, failure: str) -> None:
    database, output = tmp_path / "missing.sqlite", tmp_path / "report.html"
    if failure == "text":
        database.write_text("invalid")
    elif failure == "directory":
        database.mkdir()
    elif failure == "unsupported":
        import sqlite3
        save_review(database, machine_review)
        with sqlite3.connect(database) as connection:
            connection.execute("PRAGMA user_version = 99")
    result = run_cli("export", str(database), "--output", str(output))
    assert result.returncode == 2 and result.stdout == ""
    assert str(database) in result.stderr and "Traceback" not in result.stderr
    assert not output.exists()
    if failure == "missing":
        assert not database.exists()


def test_export_help_and_required_output() -> None:
    help_result = run_cli("export", "--help")
    assert help_result.returncode == 0 and help_result.stderr == ""
    assert "--output" in help_result.stdout
    result = run_cli("export", "review.sqlite")
    assert result.returncode == 2 and result.stdout == ""
    assert "required" in result.stderr


def test_export_and_show_never_fetch_evidence(tmp_path: Path, machine_review: ReviewResult, monkeypatch, capsys) -> None:
    from sbom_reviewer import cli, review
    database = tmp_path / "review.sqlite"
    save_review(database, machine_review)
    def forbidden_fetch(url: str):
        pytest.fail(f"Unexpected network fetch: {url}")
    monkeypatch.setattr(review, "fetch_model_card", forbidden_fetch)
    for arguments in (["show", str(database)], ["export", str(database), "--output", str(tmp_path / "report.html")]):
        monkeypatch.setattr(sys, "argv", ["sbom-reviewer", *arguments])
        cli.main()
        assert capsys.readouterr().err == ""
