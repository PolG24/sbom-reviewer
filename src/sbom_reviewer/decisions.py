"""Pure reviewer-action validation and current-human summary derivation."""

from sbom_reviewer.models import (
    Decision, DecisionEvent, PreparedDecision, ReviewerSummary, ReviewResult,
)


class DecisionError(ValueError):
    """An expected invalid reviewer action."""


def prepare_decision(
    snapshot: ReviewResult, component_id: str, *, reviewer: str, reason: str,
    confirm: bool = False, override: str | None = None,
) -> PreparedDecision:
    if confirm == (override is not None):
        raise DecisionError("Choose exactly one of confirm or override.")
    if not reviewer.strip():
        raise DecisionError("A nonblank reviewer name is required.")
    if not reason.strip():
        raise DecisionError("A nonblank reason is required.")
    component = next((item for item in snapshot.results if item.component_id == component_id), None)
    if component is None:
        raise DecisionError(f"Unknown component ID: {component_id}")
    if confirm:
        decision = component.decision
    else:
        try:
            decision = Decision(override)
        except ValueError as exc:
            raise DecisionError("Invalid outcome; choose Allow, Needs review, or Reject.") from exc
        if decision == component.decision:
            raise DecisionError("Use confirm recommendation when agreeing with the machine recommendation.")
    return PreparedDecision(component_id=component_id, action="confirm" if confirm else "override",
                            decision=decision, reviewer=reviewer, reason=reason)


def current_decisions(
    snapshot: ReviewResult, events: list[DecisionEvent],
) -> tuple[list[DecisionEvent], ReviewerSummary]:
    latest: dict[str, DecisionEvent] = {}
    for event in events:
        previous = latest.get(event.component_id)
        if previous is None or event.event_id > previous.event_id:
            latest[event.component_id] = event
    current = [latest[item.component_id] for item in snapshot.results if item.component_id in latest]
    summary = ReviewerSummary(
        total=len(snapshot.results), recorded=len(current), pending=len(snapshot.results) - len(current),
        allow=sum(item.decision == Decision.ALLOW for item in current),
        needs_review=sum(item.decision == Decision.NEEDS_REVIEW for item in current),
        reject=sum(item.decision == Decision.REJECT for item in current),
    )
    return current, summary
