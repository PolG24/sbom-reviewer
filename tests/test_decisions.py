"""Human decisions never rewrite machine evidence or imply pending approval."""

from datetime import datetime, timezone

import pytest

from sbom_reviewer.saved_reviews import decisions as api
from sbom_reviewer.models import DecisionEvent, ReviewResult


def event(review: ReviewResult, component: str, event_id: int, *,
          confirm: bool = False, override: str | None = None) -> DecisionEvent:
    prepared = api.prepare_decision(review, component, reviewer="Legal", reason="Reviewed evidence",
                                    confirm=confirm, override=override)
    return DecisionEvent(event_id=event_id, recorded_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
                         **prepared.model_dump())


@pytest.mark.parametrize("index,outcome", [(0, "Allow"), (1, "Needs review"), (2, "Reject")])
def test_confirm_uses_original_recommendation(machine_review: ReviewResult, index: int, outcome: str) -> None:
    before = machine_review.model_dump()
    prepared = api.prepare_decision(machine_review, f"#/components/{index}", confirm=True,
                                    reviewer=" Legal ", reason=" Supplied declaration checked ")
    assert prepared.action == "confirm"
    assert prepared.decision == outcome
    assert prepared.reviewer == " Legal "
    assert prepared.reason == " Supplied declaration checked "
    assert machine_review.model_dump() == before


def test_latest_event_ids_determine_ordered_current_decisions_and_counts(machine_review: ReviewResult) -> None:
    events = [event(machine_review, "#/components/2", 1, override="Allow"),
              event(machine_review, "#/components/1", 2, override="Allow"),
              event(machine_review, "#/components/2", 3, confirm=True)]
    current, summary = api.current_decisions(machine_review, events)
    assert [item.event_id for item in current] == [2, 3]
    assert [item.decision for item in current] == ["Allow", "Reject"]
    assert summary.model_dump() == {"total": 3, "recorded": 2, "pending": 1,
                                    "allow": 1, "needs_review": 0, "reject": 1}
    assert len(events) == 3
    assert machine_review.summary.model_dump() == {"total": 3, "allow": 1, "needs_review": 1, "reject": 1}


def test_pending_and_recorded_needs_review_remain_unresolved(machine_review: ReviewResult) -> None:
    current, summary = api.current_decisions(machine_review, [])
    assert current == []
    assert summary.model_dump() == {"total": 3, "recorded": 0, "pending": 3,
                                    "allow": 0, "needs_review": 0, "reject": 0}
    current, summary = api.current_decisions(machine_review, [
        event(machine_review, "#/components/1", 1, confirm=True)])
    assert summary.needs_review == 1
    assert summary.allow == 0
    assert summary.pending == 2


@pytest.mark.parametrize("changes,match", [
    ({"confirm": False}, "exactly one"),
    ({"override": "Reject"}, "exactly one"),
    ({"reviewer": " \t "}, "reviewer"),
    ({"reason": "\n"}, "reason"),
    ({"confirm": False, "override": "Allowed"}, "outcome"),
    ({"confirm": False, "override": "Allow"}, "confirm"),
    ({"component_id": "same name"}, "component"),
])
def test_invalid_actions_fail_without_changing_snapshot(machine_review: ReviewResult, changes: dict, match: str) -> None:
    before = machine_review.model_dump()
    arguments = {"component_id": "#/components/0", "confirm": True,
                 "reviewer": "Legal", "reason": "Checked"} | changes
    with pytest.raises(ValueError, match=match):
        api.prepare_decision(machine_review, **arguments)
    assert machine_review.model_dump() == before
