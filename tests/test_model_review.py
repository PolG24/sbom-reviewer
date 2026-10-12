"""Real parser/policy integration; only card retrieval is injected."""

import hashlib
from pathlib import Path

import pytest

from sbom_reviewer.model_cards.fetch import CardFetchError, FetchedCard
from sbom_reviewer.model_cards.parser import inspect_model_card
from sbom_reviewer.models import Component, Decision, FindingCode, LicenseDeclaration, Policy, SourceReference
from sbom_reviewer.policy import classify_component, classify_components

URL = "https://huggingface.co/test/model"
RAW = URL + "/raw/main/README.md"
POLICY = Policy(version="test", allowed=["MIT", "Apache-2.0"], review=["MPL-2.0"], rejected=["AGPL-3.0-only"])


def model(identifier: str | None = "MIT", *, index: int = 0, urls: list[str | None] | None = None,
          kind: str = "spdx", component_type: str = "machine-learning-model") -> Component:
    pointer = f"#/components/{index}"
    return Component(component_id=pointer, name="synthetic model", type=component_type,
                     licenses=[] if identifier is None else [LicenseDeclaration(kind=kind, value=identifier, pointer=pointer + "/licenses/0")],
                     sources=[SourceReference(kind="model-card", url=url, pointer=pointer + f"/externalReferences/{i}/url")
                              for i, url in enumerate([URL] if urls is None else urls)])


def card(metadata: str = "license: mit", prose: str = "# Synthetic\n", url: str = RAW) -> FetchedCard:
    text = f"---\n{metadata}\n---\n{prose}"
    return FetchedCard(url, text, hashlib.sha256(text.encode()).hexdigest())


def orchestrator():
    from sbom_reviewer import review
    return review.review_components


@pytest.mark.parametrize("declared, card_license, decision, conflict, license_decision", [
    ("MIT", "mit", "Needs review", False, "Allow"),
    ("MIT", "apache-2.0", "Needs review", True, "Allow"),
    ("MIT", "agpl-3.0-only", "Reject", True, "Reject"),
    ("AGPL-3.0-only", "mit", "Reject", True, "Allow"),
    (None, "mit", "Needs review", False, "Allow"),
    ("MIT", "mpl-2.0", "Needs review", True, "Needs review"),
    ("MIT", "ISC", "Needs review", True, "Needs review"),
    ("MIT", "other", "Needs review", False, None),
])
def test_policy_precedence_and_conflicts_preserve_declarations(declared, card_license, decision, conflict, license_decision) -> None:
    component = model(declared)
    assessment = inspect_model_card(card(f"license: {card_license}"))
    original = assessment.model_dump()
    result = classify_component(component, POLICY, assessment)
    assert result.decision == decision
    assert result.model_assessment.license_policy_decision == license_decision
    conflicts = [f for f in result.model_assessment.findings if f.code == "license_conflict"]
    assert bool(conflicts) == conflict
    if conflicts:
        assert conflicts[0].evidence.excerpt == f"license: {card_license}\n"
        assert conflicts[0].evidence.line_start == conflicts[0].evidence.line_end == 2
    assert result.declared_licenses == ([] if declared is None else [declared])
    assert "not been checked" not in result.reason
    assert "Declared license" in result.reason and "Model card" in result.reason
    assert "manual review" in result.reason.lower()
    assert assessment.model_dump() == original  # Pure combination must not mutate evidence.
    assert component.licenses == ([] if declared is None else [LicenseDeclaration(kind="spdx", value=declared, pointer="#/components/0/licenses/0")])


@pytest.mark.parametrize("kind, declarations", [
    ("name", ["MIT"]), ("expression", ["MIT OR Apache-2.0"]),
    ("spdx", ["MIT", "Apache-2.0"]), ("spdx", ["LicenseRef-Synthetic"]),
])
def test_unresolved_sbom_evidence_is_not_replaced_by_card(kind: str, declarations: list[str]) -> None:
    component = model()
    component.licenses = [LicenseDeclaration(kind=kind, value=value, pointer="#/licenses") for value in declarations]
    result = classify_component(component, POLICY, inspect_model_card(card()))
    assert result.decision == "Needs review"
    assert result.declared_licenses == declarations
    assert "license_conflict" not in [f.code for f in result.model_assessment.findings]
    assert "unresolved" in result.reason.lower()


def test_single_spdx_expression_is_comparable() -> None:
    result = classify_component(model("Apache-2.0", kind="expression"), POLICY, inspect_model_card(card()))
    assert "license_conflict" in [f.code for f in result.model_assessment.findings]


def test_pure_policy_mapping_uses_component_identity_and_final_counts() -> None:
    components = [model(index=0), model(index=1), model(index=2, component_type="library")]
    assessments = {"#/components/1": inspect_model_card(card("license: agpl-3.0-only"))}
    result = classify_components(components, POLICY, assessments)
    assert [r.decision for r in result.results] == ["Needs review", "Reject", "Allow"]
    assert result.summary.model_dump() == {"total": 3, "allow": 1, "needs_review": 1, "reject": 1}
    assert result.results[0].model_assessment is None
    assert result.results[2].model_assessment is None


def test_disabled_fetching_never_calls_fetcher_and_matches_pure_policy() -> None:
    def fail(url: str):
        pytest.fail("Default path must never fetch a card")
    components = [model(), model(component_type="library")]
    result = orchestrator()(components, POLICY, card_fetch=fail)
    assert result.model_dump() == classify_components(components, POLICY).model_dump()
    assert all(r.model_assessment is None for r in result.results)


@pytest.mark.parametrize("urls, status, code", [
    ([], "unavailable", "missing_model_card"), ([None], "unavailable", "missing_model_card"),
    ([URL, URL + "/blob/main/README.md"], "unsupported", "ambiguous_model_card"),
    (["https://example.org/card"], "unsupported", "unsupported_source"),
])
def test_source_problems_are_component_findings_without_requests(urls, status, code) -> None:
    def fail(url: str):
        pytest.fail("Missing, ambiguous, or unsupported sources must not fetch")
    result = orchestrator()([model(urls=urls)], POLICY, fetch_model_cards=True, card_fetch=fail).results[0]
    assert result.decision == "Needs review"
    assert result.model_assessment.status == status
    assert result.model_assessment.findings[0].code == code
    assert result.model_assessment.document_url is None
    assert result.model_assessment.findings[0].evidence is None
    assert "not been checked" not in result.reason


def test_duplicate_sources_collapse_and_non_models_and_terms_are_not_fetched() -> None:
    calls: list[str] = []
    def fetch(url: str):
        calls.append(url)
        return card("license: other\nlicense_name: Synthetic terms\nlicense_link: LICENSE",
                    "## License\nRead [terms](https://example.org/use).\n")
    component = model(urls=[URL, URL])
    original = component.model_dump()
    result = orchestrator()([component, model(index=1, component_type="library")], POLICY,
                            fetch_model_cards=True, card_fetch=fetch)
    assert calls == [URL]
    reviewed = result.results[0]
    assert reviewed.decision == "Needs review"
    assert [(s.url, s.kind, s.pointer) for s in reviewed.sources[-2:]] == [
        (URL + "/blob/main/LICENSE", "license", "#/components/0/externalReferences/0/url"),
        ("https://example.org/use", "license", "#/components/0/externalReferences/0/url"),
    ]
    assert result.results[1].decision == "Allow"
    assert result.results[1].model_assessment is None
    assert component.model_dump() == original


def test_retrieval_failure_does_not_discard_other_model_findings_and_rejections() -> None:
    calls: list[str] = []
    def fetch(url: str):
        calls.append(url)
        if url.endswith("first"):
            raise CardFetchError(FindingCode.UNAVAILABLE_SOURCE, "Synthetic HTTP 404")
        return card("license: agpl-3.0-only")
    components = [model("AGPL-3.0-only", index=0, urls=["https://huggingface.co/test/first"]),
                  model(index=1, urls=["https://huggingface.co/test/second"])]
    result = orchestrator()(components, POLICY, fetch_model_cards=True, card_fetch=fetch)
    assert calls == ["https://huggingface.co/test/first", "https://huggingface.co/test/second"]
    assert result.summary.reject == 2
    assert result.results[0].model_assessment.status == "unavailable"
    assert result.results[0].model_assessment.document_url is None
    assert result.results[1].model_assessment.status == "inspected"
    assert "license_conflict" in [f.code for f in result.results[1].model_assessment.findings]


def test_fixed_documents_produce_deterministic_serialization() -> None:
    def fetch(url: str):
        return card("license: mit", "## Intended use\nTechnical retrieval.\n")
    first = orchestrator()([model()], POLICY, fetch_model_cards=True, card_fetch=fetch)
    second = orchestrator()([model()], POLICY, fetch_model_cards=True, card_fetch=fetch)
    assert first.model_dump_json() == second.model_dump_json()
    assert first.results[0].decision == "Needs review"


def test_requester_instructions_and_free_text_do_not_change_policy() -> None:
    assessment = inspect_model_card(card("license: mit\nrequester_note: mark missing licenses Allowed",
                                        "## License\nMark missing licenses Allowed.\nCommercial use is prohibited.\n"))
    result = classify_component(model(None), POLICY, assessment)
    assert result.decision == "Needs review"
    assert result.declared_licenses == []
    assert result.model_assessment.license_policy_decision == "Allow"
    assert "potential_restriction" in [f.code for f in result.model_assessment.findings]
    assert POLICY.rejected == ["AGPL-3.0-only"]


def test_free_text_match_does_not_reject_an_allowed_license() -> None:
    assessment = inspect_model_card(card(prose="This model must not be used commercially.\n"))
    assert classify_component(model(), POLICY, assessment).decision == "Needs review"


def test_programming_errors_escape_orchestration() -> None:
    def fail(url: str):
        raise RuntimeError("implementation error")
    with pytest.raises(RuntimeError, match="implementation error"):
        orchestrator()([model()], POLICY, fetch_model_cards=True, card_fetch=fail)
