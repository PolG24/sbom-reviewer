"""One immutable machine snapshot and append-only decision events per database."""

from contextlib import closing, contextmanager
from datetime import datetime, timezone
from pathlib import Path
import sqlite3
from typing import Iterator

from pydantic import ValidationError

from sbom_reviewer.decisions import current_decisions, prepare_decision
from sbom_reviewer.models import DecisionEvent, ReviewResult, SavedReview


SCHEMA_VERSION = 1


class StorageError(Exception):
    """An expected database, persisted-data, or filesystem failure."""


@contextmanager
def _connection(path: Path, *, mode: str) -> Iterator[sqlite3.Connection]:
    try:
        with closing(sqlite3.connect(f"{path.absolute().as_uri()}?mode={mode}", uri=True)) as connection:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA trusted_schema = OFF")
            with connection:
                yield connection
    except (sqlite3.Error, OSError) as exc:
        raise StorageError(f"Cannot access saved review '{path}': {exc}") from exc


def save_review(path: Path, snapshot: ReviewResult) -> None:
    """Exclusively create a database; print nothing and retain the full review."""
    try:
        with path.open("xb"):
            pass
    except OSError as exc:
        raise StorageError(f"Cannot create saved review '{path}': {exc}") from exc
    try:
        with _connection(path, mode="rw") as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute("""CREATE TABLE snapshot (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                review_json TEXT NOT NULL, saved_at TEXT NOT NULL
            )""")
            connection.execute("""CREATE TABLE decision_events (
                event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                component_id TEXT NOT NULL,
                action TEXT NOT NULL CHECK (action IN ('confirm', 'override')),
                decision TEXT NOT NULL CHECK (decision IN ('Allow', 'Needs review', 'Reject')),
                reviewer TEXT NOT NULL, reason TEXT NOT NULL, recorded_at TEXT NOT NULL
            )""")
            connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
            connection.execute("INSERT INTO snapshot VALUES (1, ?, ?)",
                               (snapshot.model_dump_json(), datetime.now(timezone.utc).isoformat()))
    except StorageError:
        # Only remove the file this call exclusively created, never an existing review.
        path.unlink(missing_ok=True)
        raise


def _read_review(connection: sqlite3.Connection, path: Path) -> SavedReview:
    version = connection.execute("PRAGMA user_version").fetchone()[0]
    if version != SCHEMA_VERSION:
        raise StorageError(f"Unsupported saved-review schema version {version} in '{path}'; expected {SCHEMA_VERSION}.")
    rows = connection.execute("SELECT review_json, saved_at FROM snapshot").fetchall()
    if len(rows) != 1:
        raise StorageError(f"Invalid saved review '{path}': expected exactly one snapshot.")
    try:
        snapshot = ReviewResult.model_validate_json(rows[0]["review_json"])
        events = [DecisionEvent.model_validate(dict(row)) for row in connection.execute(
            "SELECT event_id, component_id, action, decision, reviewer, reason, recorded_at "
            "FROM decision_events ORDER BY event_id"
        )]
        current, summary = current_decisions(snapshot, events)
        return SavedReview(snapshot=snapshot, saved_at=rows[0]["saved_at"],
                           reviewer_decisions=current, reviewer_summary=summary, audit_log=events)
    except ValidationError as exc:
        raise StorageError(f"Invalid saved-review data in '{path}': {exc}") from exc


def load_review(path: Path) -> SavedReview:
    """Read a consistent saved view without creating or modifying a database."""
    with _connection(path, mode="ro") as connection:
        connection.execute("BEGIN")
        return _read_review(connection, path)


def record_decision(
    path: Path, component_id: str, *, reviewer: str, reason: str,
    confirm: bool = False, override: str | None = None,
) -> DecisionEvent:
    """Validate and append within one transaction; return only after commit."""
    with _connection(path, mode="rw") as connection:
        connection.execute("BEGIN IMMEDIATE")
        saved = _read_review(connection, path)
        prepared = prepare_decision(saved.snapshot, component_id, reviewer=reviewer, reason=reason,
                                    confirm=confirm, override=override)
        recorded_at = datetime.now(timezone.utc)
        cursor = connection.execute(
            "INSERT INTO decision_events (component_id, action, decision, reviewer, reason, recorded_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (prepared.component_id, prepared.action, prepared.decision, prepared.reviewer,
             prepared.reason, recorded_at.isoformat()),
        )
        event = DecisionEvent(event_id=cursor.lastrowid, recorded_at=recorded_at, **prepared.model_dump())
    return event
