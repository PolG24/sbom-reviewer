"""Real SQLite persistence, event isolation, and transactional failure cases."""

from pathlib import Path
import sqlite3

import pytest

from sbom_reviewer import storage as api
from sbom_reviewer.models import ReviewResult



def test_roundtrip_retains_complete_evidence_and_independent_reviews(tmp_path: Path, machine_review: ReviewResult) -> None:
    first, second = tmp_path / "first.sqlite", tmp_path / "second.sqlite"
    api.save_review(first, machine_review)
    api.save_review(second, machine_review)
    saved = api.load_review(first)
    assert saved.snapshot.model_dump() == machine_review.model_dump()
    assert saved.saved_at.utcoffset().total_seconds() == 0
    assert saved.audit_log == saved.reviewer_decisions == []
    assert saved.reviewer_summary.pending == 3
    original_saved_at = saved.saved_at
    event = api.record_decision(first, "#/components/1", override="Allow", reviewer="Legal", reason="Explicit exception")
    assert event.event_id == 1
    assert event.recorded_at.utcoffset().total_seconds() == 0
    assert event.action == "override" and event.decision == "Allow"
    saved = api.load_review(first)
    assert saved.snapshot.model_dump() == machine_review.model_dump()
    assert saved.saved_at == original_saved_at
    assert saved.audit_log == saved.reviewer_decisions == [event]
    assert api.load_review(second).audit_log == []


def test_history_is_append_only_and_confirm_restores_original(tmp_path: Path, machine_review: ReviewResult) -> None:
    path = tmp_path / "review.sqlite"
    api.save_review(path, machine_review)
    first = api.record_decision(path, "#/components/2", override="Allow", reviewer="One", reason="Demo override")
    second = api.record_decision(path, "#/components/2", confirm=True, reviewer="Two", reason="Return to policy")
    third = api.record_decision(path, "#/components/2", confirm=True, reviewer="Two", reason="Rechecked")
    assert [first.event_id, second.event_id, third.event_id] == [1, 2, 3]
    view = api.load_review(path)
    assert view.audit_log == [first, second, third]
    assert view.reviewer_decisions == [third]
    assert view.reviewer_summary.model_dump() == {"total": 3, "recorded": 1, "pending": 2,
                                               "allow": 0, "needs_review": 0, "reject": 1}


@pytest.mark.parametrize("arguments", [
    {"component_id": "same name", "confirm": True},
    {"component_id": "#/components/0", "override": "Allow"},
    {"component_id": "#/components/0", "confirm": True, "reviewer": " "},
    {"component_id": "#/components/0", "confirm": True, "reason": " "},
])
def test_invalid_action_keeps_existing_history(tmp_path: Path, machine_review: ReviewResult, arguments: dict) -> None:
    path = tmp_path / "review.sqlite"
    api.save_review(path, machine_review)
    api.record_decision(path, "#/components/0", confirm=True, reviewer="Legal", reason="Checked")
    before = api.load_review(path)
    with pytest.raises(ValueError):
        api.record_decision(path, **({"reviewer": "Legal", "reason": "Checked"} | arguments))
    assert api.load_review(path) == before


def test_sqlite_failed_append_rolls_back_and_remains_loadable(tmp_path: Path, machine_review: ReviewResult) -> None:
    path = tmp_path / "review.sqlite"
    api.save_review(path, machine_review)
    before = api.load_review(path)
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TRIGGER refuse_events BEFORE INSERT ON decision_events BEGIN SELECT RAISE(ABORT, 'synthetic write failure'); END")
    with pytest.raises(api.StorageError, match="synthetic write failure"):
        api.record_decision(path, "#/components/0", confirm=True, reviewer="Legal", reason="Checked")
    assert api.load_review(path) == before


@pytest.mark.parametrize("failure", ["missing", "directory", "text", "empty", "unsupported", "corrupt_snapshot"])
def test_invalid_databases_are_clear_errors_and_never_created(tmp_path: Path, machine_review: ReviewResult, failure: str) -> None:
    path = tmp_path / "review.sqlite"
    if failure == "directory":
        path.mkdir()
    elif failure == "text":
        path.write_text("not a database")
    elif failure == "empty":
        path.touch()
    elif failure in {"unsupported", "corrupt_snapshot"}:
        api.save_review(path, machine_review)
        with sqlite3.connect(path) as connection:
            if failure == "unsupported":
                connection.execute("PRAGMA user_version = 99")
            else:
                connection.execute("UPDATE snapshot SET review_json = '{}' WHERE id = 1")
    for operation in (lambda: api.load_review(path), lambda: api.record_decision(
        path, "#/components/0", confirm=True, reviewer="Legal", reason="Checked")):
        with pytest.raises(api.StorageError) as error:
            operation()
        assert str(path) in str(error.value)
        if failure == "unsupported":
            assert "version" in str(error.value).lower()
    if failure == "missing":
        assert not path.exists()


def test_existing_snapshot_is_not_overwritten_and_missing_parent_is_error(tmp_path: Path, machine_review: ReviewResult) -> None:
    path = tmp_path / "review.sqlite"
    path.write_bytes(b"preserve me")
    with pytest.raises(api.StorageError, match="exist"):
        api.save_review(path, machine_review)
    assert path.read_bytes() == b"preserve me"
    with pytest.raises(api.StorageError):
        api.save_review(tmp_path / "missing" / "review.sqlite", machine_review)
