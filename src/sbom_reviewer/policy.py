"""Local policy loading and deterministic declared-license recommendations."""

import re
from collections.abc import Mapping
from pathlib import Path

from cyclonedx.spdx import is_supported_id

from sbom_reviewer.json_input import parse_json
from sbom_reviewer.models import (
    Component, ComponentResult, Decision, FindingCode, LicenseDeclaration,
    ModelAssessment, ModelFinding, Policy, ReviewResult, Summary,
)


def load_policy(path: Path) -> Policy:
    return Policy.model_validate(parse_json(path.read_text(encoding="utf-8")))


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


def _comparable_license(licenses: list[LicenseDeclaration]) -> str | None:
    if len(licenses) == 1 and licenses[0].kind != "name" and is_supported_id(licenses[0].value):
        return licenses[0].value
    return None


def _assess_license(component: Component, policy: Policy, assessment: ModelAssessment) -> tuple[ModelAssessment, str]:
    assessment = assessment.model_copy(deep=True)
    identifier = assessment.normalized_license
    card_reason = "No supported card metadata license is available."
    if identifier is not None:
        assessment.license_policy_decision, card_reason = classify_licenses(
            [LicenseDeclaration(kind="spdx", value=identifier, pointer="")], policy,
        )
        declared = _comparable_license(component.licenses)
        if declared is None:
            card_reason += " SBOM license comparison remains unresolved."
        elif declared != identifier:
            conflict = ModelFinding(code=FindingCode.LICENSE_CONFLICT,
                                    message=f"SBOM license {declared!r} differs from card metadata {identifier!r}.",
                                    evidence=assessment.license_evidence)
            prose_codes = {FindingCode.USAGE_CONTEXT, FindingCode.POTENTIAL_RESTRICTION,
                           FindingCode.REFERENCED_TERMS_UNREAD, FindingCode.NO_SUPPORTED_INDICATORS}
            position = next((i for i, finding in enumerate(assessment.findings)
                             if finding.code in prose_codes), len(assessment.findings))
            assessment.findings.insert(position, conflict)
    return assessment, card_reason


def classify_component(component: Component, policy: Policy,
                       assessment: ModelAssessment | None = None) -> ComponentResult:
    decision, reason = classify_licenses(component.licenses, policy)
    if component.type == "machine-learning-model":
        if assessment is not None:
            assessment, card_reason = _assess_license(component, policy, assessment)
            if assessment.license_policy_decision == Decision.REJECT:
                decision = Decision.REJECT
        if decision != Decision.REJECT:
            decision = Decision.NEEDS_REVIEW
        if assessment is None:
            reason += " Model assessment: model-card restrictions have not been checked yet."
        else:
            findings = " ".join(finding.message for finding in assessment.findings)
            reason = (f"Declared license: {reason} Model card ({assessment.status}): {card_reason} "
                      f"{findings} Model terms and intended product use still require manual review.")
    else:
        assessment = None
    return ComponentResult(
        component_id=component.component_id, bom_ref=component.bom_ref,
        name=component.name, version=component.version, type=component.type,
        declared_licenses=[license.value for license in component.licenses],
        decision=decision, reason=reason, sources=component.sources, model_assessment=assessment,
    )


def classify_components(components: list[Component], policy: Policy,
                        assessments: Mapping[str, ModelAssessment] | None = None) -> ReviewResult:
    results = [classify_component(component, policy, (assessments or {}).get(component.component_id))
               for component in components]
    return ReviewResult(
        policy_version=policy.version, results=results,
        summary=Summary(
            total=len(results),
            allow=sum(result.decision == Decision.ALLOW for result in results),
            needs_review=sum(result.decision == Decision.NEEDS_REVIEW for result in results),
            reject=sum(result.decision == Decision.REJECT for result in results),
        ),
    )
