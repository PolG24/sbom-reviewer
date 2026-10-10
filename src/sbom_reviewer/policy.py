"""Local policy loading and deterministic declared-license recommendations."""

import json
import re
from pathlib import Path

from cyclonedx.spdx import is_supported_id

from sbom_reviewer.models import (
    Component, ComponentResult, Decision, LicenseDeclaration, Policy, ReviewResult, Summary,
)


def load_policy(path: Path) -> Policy:
    return Policy.model_validate(json.loads(path.read_text(encoding="utf-8")))


def classify_licenses(licenses: list[LicenseDeclaration], policy: Policy) -> tuple[Decision, str]:
    if not licenses:
        return Decision.NEEDS_REVIEW, "License evidence is missing."
    if len(licenses) != 1:
        return Decision.NEEDS_REVIEW, "Multiple license entries: license selection semantics require review."

    declaration = licenses[0]
    identifier = declaration.value
    if declaration.kind == "expression" and re.search(r"\b(?:AND|OR|WITH)\b|[()]", identifier):
        return Decision.NEEDS_REVIEW, f"License expression {identifier!r}: expression semantics require review."
    if declaration.kind == "name" or identifier.startswith("LicenseRef-"):
        return Decision.NEEDS_REVIEW, f"License {identifier!r} is custom; licensing evidence requires review."
    if is_supported_id(identifier):
        for category, decision in (
            ("rejected", Decision.REJECT),
            ("review", Decision.NEEDS_REVIEW),
            ("allowed", Decision.ALLOW),
        ):
            if identifier in getattr(policy, category):
                return decision, f"{identifier} matches the {category} category in policy version {policy.version}."
    return Decision.NEEDS_REVIEW, f"License {identifier!r} is unknown to policy version {policy.version}."


def classify_component(component: Component, policy: Policy) -> ComponentResult:
    decision, reason = classify_licenses(component.licenses, policy)
    if component.type == "machine-learning-model":
        if decision != Decision.REJECT:
            decision = Decision.NEEDS_REVIEW
        reason += " Model assessment: model-card restrictions have not been checked yet."
    return ComponentResult(
        component_id=component.component_id, bom_ref=component.bom_ref,
        name=component.name, version=component.version, type=component.type,
        declared_licenses=[license.value for license in component.licenses],
        decision=decision, reason=reason, sources=component.sources,
    )


def review_components(components: list[Component], policy: Policy) -> ReviewResult:
    results = [classify_component(component, policy) for component in components]
    return ReviewResult(
        policy_version=policy.version, results=results,
        summary=Summary(
            total=len(results),
            allow=sum(result.decision == Decision.ALLOW for result in results),
            needs_review=sum(result.decision == Decision.NEEDS_REVIEW for result in results),
            reject=sum(result.decision == Decision.REJECT for result in results),
        ),
    )
