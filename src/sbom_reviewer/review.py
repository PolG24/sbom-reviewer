"""Opt-in, sequential evidence collection before pure policy review."""

from collections.abc import Callable

from sbom_reviewer import policy as license_policy
from sbom_reviewer.model_card_fetch import (
    CardFetchError, FetchedCard, fetch_model_card, normalize_model_card_url,
)
from sbom_reviewer.model_cards import inspect_model_card, referenced_terms
from sbom_reviewer.models import (
    Component, FindingCode, ModelAssessment, ModelFinding, Policy, ReviewResult, SourceReference,
)


def _source_problem(code: FindingCode, message: str) -> ModelAssessment:
    status = "unsupported" if code in {FindingCode.UNSUPPORTED_SOURCE, FindingCode.AMBIGUOUS_MODEL_CARD} else "unavailable"
    return ModelAssessment(status=status, findings=[ModelFinding(code=code, message=message)])


def _inspect_component(component: Component, card_fetch: Callable[[str], FetchedCard]) -> tuple[Component, ModelAssessment]:
    references = {source.url: source for source in reversed(component.sources)
                  if source.kind == "model-card" and source.url}
    if not references:
        return component, _source_problem(FindingCode.MISSING_MODEL_CARD, "No usable model-card reference is present in the SBOM.")
    if len(references) != 1:
        return component, _source_problem(FindingCode.AMBIGUOUS_MODEL_CARD, "Multiple distinct model-card references; no card was selected.")
    url, source = next(iter(references.items()))
    try:
        normalize_model_card_url(url)
        card = card_fetch(url)
    except CardFetchError as exc:
        return component, _source_problem(exc.code, str(exc))
    assessment = inspect_model_card(card)
    sources = list(component.sources)
    for link, _ in referenced_terms(card):
        reference = SourceReference(url=link, kind="license", pointer=source.pointer)
        if reference not in sources:
            sources.append(reference)
    return component.model_copy(update={"sources": sources}), assessment


def review_components(components: list[Component], policy: Policy, *, fetch_model_cards: bool = False,
                      card_fetch: Callable[[str], FetchedCard] | None = None) -> ReviewResult:
    if not fetch_model_cards:
        return license_policy.review_components(components, policy)
    fetch = card_fetch if card_fetch is not None else fetch_model_card
    assessments: dict[str, ModelAssessment] = {}
    collected: list[Component] = []
    for component in components:
        if component.type == "machine-learning-model":
            component, assessment = _inspect_component(component, fetch)
            assessments[component.component_id] = assessment
        collected.append(component)
    return license_policy.review_components(collected, policy, assessments)
