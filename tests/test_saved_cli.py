"""Installed CLI contracts for saving, human decisions, and inspection."""

import json
from pathlib import Path
import sys
import sqlite3

import pytest

from sbom_reviewer.models import ReviewResult
from sbom_reviewer.storage import load_review, save_review
from test_cli import run_cli, write_inputs


def test_optional_save_emits_unchanged_review_and_default_creates_no_database(tmp_path: Path) -> None:
    sbom, policy = write_inputs(tmp_path, [{"type": "library", "name": "missing"}])
    original = run_cli("review", str(sbom), "--policy", str(policy))
    assert original.returncode == 0
    assert {path.name for path in tmp_path.iterdir()} == {"bom.json", "policy.json"}
    path = tmp_path / "review.sqlite"
    saved = run_cli("review", str(sbom), "--policy", str(policy), "--save-review", str(path))
    assert saved.returncode == 0
    assert saved.stderr == ""
    assert saved.stdout == original.stdout
    assert load_review(path).snapshot.model_dump(mode="json") == json.loads(original.stdout)


def test_save_failure_has_no_success_json_and_preserves_existing_file(tmp_path: Path) -> None:
    sbom, policy = write_inputs(tmp_path)
    path = tmp_path / "review.sqlite"
    path.write_bytes(b"preserve")
    for target in (path, tmp_path / "missing" / "review.sqlite"):
        result = run_cli("review", str(sbom), "--policy", str(policy), "--save-review", str(target))
        assert result.returncode == 2
        assert result.stdout == ""
        assert str(target) in result.stderr
        assert "Traceback" not in result.stderr
    assert path.read_bytes() == b"preserve"


@pytest.mark.parametrize("index,outcome", [(0, "Allow"), (1, "Needs review"), (2, "Reject")])
def test_confirm_cli_records_machine_outcomes_with_exit_zero(tmp_path: Path, machine_review: ReviewResult, index: int, outcome: str) -> None:
    path = tmp_path / "review.sqlite"
    save_review(path, machine_review)
    result = run_cli("decide", str(path), "--component", f"#/components/{index}", "--confirm",
                     "--reviewer", "Legal", "--reason", "Reviewed declaration")
    assert result.returncode == 0
    assert result.stderr == ""
    event = json.loads(result.stdout)
    assert event["decision"] == outcome and event["action"] == "confirm"
    assert event["event_id"] == 1
    assert event["reviewer"] == "Legal" and event["reason"] == "Reviewed declaration"
    assert set(event) == {"event_id", "component_id", "action", "decision", "reviewer", "reason", "recorded_at"}


def test_show_orders_current_decisions_and_retains_complete_audit(tmp_path: Path, machine_review: ReviewResult) -> None:
    path = tmp_path / "review.sqlite"
    save_review(path, machine_review)
    for component, action in [(2, ["--override", "Allow"]), (1, ["--override", "Allow"]), (2, ["--confirm"])]:
        result = run_cli("decide", str(path), "--component", f"#/components/{component}", *action,
                         "--reviewer", "Legal", "--reason", "Demo action")
        assert result.returncode == 0 and result.stderr == ""
    result = run_cli("show", str(path))
    assert result.returncode == 0 and result.stderr == ""
    view = json.loads(result.stdout)
    assert set(view) == {"snapshot", "saved_at", "reviewer_decisions", "audit_log", "reviewer_summary"}
    assert view["snapshot"] == machine_review.model_dump(mode="json")
    assert [event["event_id"] for event in view["audit_log"]] == [1, 2, 3]
    assert [event["event_id"] for event in view["reviewer_decisions"]] == [2, 3]
    assert view["reviewer_summary"] == {"total": 3, "recorded": 2, "pending": 1,
                                      "allow": 1, "needs_review": 0, "reject": 1}


@pytest.mark.parametrize("flags,match", [
    ([], "required"), (["--confirm", "--override", "Reject"], "not allowed"),
    (["--override", "Allowed"], "invalid choice"), (["--override", "Allow"], "confirm"),
    (["--confirm", "--reviewer", " "], "reviewer"),
    (["--confirm", "--reason", "\n"], "reason"),
    (["--confirm", "--component", "same name"], "component"),
])
def test_invalid_decisions_do_not_print_success_or_mutate_history(tmp_path: Path, machine_review: ReviewResult, flags: list[str], match: str) -> None:
    path = tmp_path / "review.sqlite"
    save_review(path, machine_review)
    before = path.read_bytes()
    result = run_cli("decide", str(path), "--component", "#/components/0",
                     "--reviewer", "Legal", "--reason", "Reviewed", *flags)
    assert result.returncode == 2
    assert result.stdout == ""
    assert match in result.stderr and "Traceback" not in result.stderr
    assert path.read_bytes() == before


@pytest.mark.parametrize("command,flags", [("show", []), ("decide", ["--component", "#/components/0", "--confirm", "--reviewer", "Legal", "--reason", "Checked"])])
@pytest.mark.parametrize("kind", ["missing", "text", "directory"])
def test_database_cli_errors_do_not_create_files(tmp_path: Path, command: str, flags: list[str], kind: str) -> None:
    path = tmp_path / "review.sqlite"
    if kind == "text":
        path.write_text("invalid")
    elif kind == "directory":
        path.mkdir()
    result = run_cli(command, str(path), *flags)
    assert result.returncode == 2
    assert result.stdout == ""
    assert str(path) in result.stderr and "Traceback" not in result.stderr
    if kind == "missing":
        assert not path.exists()


@pytest.mark.parametrize("arguments,expected", [
    (["--help"], "decide"), (["review", "--help"], "--save-review"),
    (["decide", "--help"], "--confirm"), (["show", "--help"], "review"),
])
def test_saved_review_help(arguments: list[str], expected: str) -> None:
    result = run_cli(*arguments)
    assert result.returncode == 0 and result.stderr == ""
    assert expected in result.stdout


def test_save_with_opt_in_fetch_preserves_inspected_card(tmp_path: Path, monkeypatch, capsys) -> None:
    from sbom_reviewer import cli, review
    from sbom_reviewer.model_card_fetch import FetchedCard
    import hashlib

    sbom, policy = write_inputs(tmp_path, [{"type": "machine-learning-model", "name": "model",
        "externalReferences": [{"type": "model-card", "url": "https://huggingface.co/test/model"}]}])
    document = "---\nlicense: mit\n---\n# License\nSynthetic license evidence.\n"
    def fetch(url: str) -> FetchedCard:
        assert url == "https://huggingface.co/test/model"
        return FetchedCard(url + "/raw/main/README.md", document, hashlib.sha256(document.encode()).hexdigest())
    monkeypatch.setattr(review, "fetch_model_card", fetch)
    path = tmp_path / "review.sqlite"
    monkeypatch.setattr(sys, "argv", ["sbom-reviewer", "review", str(sbom), "--policy", str(policy),
                                     "--fetch-model-cards", "--save-review", str(path)])
    cli.main()
    captured = capsys.readouterr()
    assert captured.err == ""
    saved = load_review(path)
    assert saved.snapshot.model_dump(mode="json") == json.loads(captured.out)
    assert saved.snapshot.results[0].model_assessment.status == "inspected"
    assert saved.snapshot.results[0].model_assessment.license_evidence.excerpt == "license: mit\n"
    assert saved.snapshot.results[0].decision == "Needs review"


def test_default_review_never_opens_a_database(tmp_path: Path, monkeypatch, capsys) -> None:
    from sbom_reviewer import cli
    sbom, policy = write_inputs(tmp_path)
    def forbidden_connection(*args, **kwargs):
        pytest.fail("Default review opened a database")
    monkeypatch.setattr(sqlite3, "connect", forbidden_connection)
    monkeypatch.setattr(sys, "argv", ["sbom-reviewer", "review", str(sbom), "--policy", str(policy)])
    cli.main()
    captured = capsys.readouterr()
    assert captured.err == ""
    assert json.loads(captured.out)["summary"]["total"] == 0


def test_failed_commit_does_not_emit_event_json_or_leave_history(tmp_path: Path, machine_review: ReviewResult) -> None:
    from contextlib import closing
    path = tmp_path / "review.sqlite"
    save_review(path, machine_review)
    before = load_review(path)
    # A live reader permits INSERT but blocks the writer's commit in rollback-journal mode.
    with closing(sqlite3.connect(path)) as reader:
        reader.execute("BEGIN")
        reader.execute("SELECT * FROM snapshot").fetchall()
        result = run_cli("decide", str(path), "--component", "#/components/0", "--confirm",
                         "--reviewer", "Legal", "--reason", "Checked")
        assert result.returncode == 2 and result.stdout == ""
        assert "locked" in result.stderr and "Traceback" not in result.stderr
        reader.rollback()
    assert load_review(path) == before


@pytest.mark.parametrize("flags", [[], ["--reviewer", "Legal"], ["--reason", "Checked"]])
def test_decide_requires_reviewer_and_reason(flags: list[str]) -> None:
    result = run_cli("decide", "review.sqlite", "--component", "#/components/0", "--confirm", *flags)
    assert result.returncode == 2 and result.stdout == ""
    assert "required" in result.stderr and "Traceback" not in result.stderr
