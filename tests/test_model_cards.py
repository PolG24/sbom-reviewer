"""Synthetic evidence contracts: incorrect normalization or lost provenance must fail."""

import hashlib
from pathlib import Path

import pytest

from sbom_reviewer import models

FIXTURES = Path(__file__).parent / "fixtures/model_cards"
URL = "https://huggingface.co/test/model/raw/main/README.md"


def inspect(text: str):
    # Import at use time so the first red run reports the missing behavior clearly.
    from sbom_reviewer.model_card_fetch import FetchedCard
    from sbom_reviewer.model_cards import inspect_model_card
    return inspect_model_card(FetchedCard(URL, text, hashlib.sha256(text.encode()).hexdigest()))


def codes(assessment) -> list[str]:
    return [finding.code.value for finding in assessment.findings]


def test_assessment_contract_exists_and_serializes_missing_evidence() -> None:
    assert hasattr(models, "ModelAssessment"), "STORY-002 assessment model is missing"
    assessment = models.ModelAssessment(status="unavailable", findings=[
        models.ModelFinding(code="missing_model_card", message="No model-card reference.")])
    data = assessment.model_dump(mode="json")
    assert data["document_url"] is None and data["document_sha256"] is None
    assert data["license_policy_decision"] is None
    assert data["findings"][0]["evidence"] is None


@pytest.mark.parametrize("label, identifier", [
    ("mit", "MIT"), ("apache-2.0", "Apache-2.0"), ("bsd-3-clause", "BSD-3-Clause"),
    ("mpl-2.0", "MPL-2.0"), ("lgpl-3.0-only", "LGPL-3.0-only"),
    ("agpl-3.0-only", "AGPL-3.0-only"), ("cc-by-nc-4.0", "CC-BY-NC-4.0"),
    ("cc-by-nc-sa-4.0", "CC-BY-NC-SA-4.0"), ("MIT", "MIT"),
    ("Apache-2.0", "Apache-2.0"), ("ISC", "ISC"),
])
def test_metadata_normalization_preserves_original(label: str, identifier: str) -> None:
    result = inspect(f"---\nlicense: {label}\n---\n# Synthetic\n")
    assert result.card_license == label
    assert result.normalized_license == identifier
    assert result.license_policy_decision is None
    assert result.status == "inspected"
    assert result.document_url == URL
    if identifier.startswith("CC-BY-NC"):
        finding = result.findings[0]
        assert finding.code == "restricted_license"
        assert finding.evidence.excerpt == f"license: {label}\n"
        assert (finding.evidence.line_start, finding.evidence.line_end) == (2, 2)
    assert codes(result)[-1] == "no_supported_indicators"
    assert result.findings[-1].message == "No supported restriction indicators detected; manual review is still required."


@pytest.mark.parametrize("metadata, expected", [
    ("license: other\nlicense_name: Synthetic RAIL", "custom_license"),
    ("license: LicenseRef-Synthetic", "custom_license"),
    ("license: strange\nlicense_name: Named terms", "custom_license"),
    ("license: apache", "unknown_license"), ("license: MIT-like", "unknown_license"),
    ("license: ''", "missing_license"), ("language: en", "missing_license"),
    ("license: [mit, apache-2.0]", "invalid_metadata"),
    ("license: 12", "invalid_metadata"), ("license: null", "invalid_metadata"),
    ("license: mit\nlicense_name: []", "invalid_metadata"),
    ("license: mit\nlicense_link: false", "invalid_metadata"),
    ("license: mit\nlicense: apache-2.0", "invalid_metadata"),
    ("language: en\nlanguage: es\nlicense: mit", "invalid_metadata"),
    ("license: [broken", "invalid_metadata"),
    ("license: !!python/object/apply:os.system ['exit 99']", "invalid_metadata"),
    ("[mit, apache-2.0]", "invalid_metadata"),
])
def test_untrusted_metadata_produces_review_findings(metadata: str, expected: str) -> None:
    text = f"---\n{metadata}\n---\n\n## Limitations\nTechnical context.\n"
    result = inspect(text)
    assert expected in codes(result)
    assert "usage_context" in codes(result)
    finding = next(f for f in result.findings if f.code == expected)
    if expected == "missing_license" and metadata == "language: en":
        assert finding.evidence is None
    else:
        assert finding.evidence is not None
        assert finding.evidence.document_url == URL
    if expected in {"custom_license", "unknown_license"}:
        assert result.normalized_license is None


@pytest.mark.parametrize("text, expected", [
    ("# Synthetic\n\n## License\nRead the license.\n", "missing_license"),
    ("---\nlicense: mit\n## Limitations\nContext.\n", "invalid_metadata"),
])
def test_missing_or_unclosed_frontmatter_keeps_supported_prose(text: str, expected: str) -> None:
    result = inspect(text)
    assert expected in codes(result)
    assert "usage_context" in codes(result)
    assert result.normalized_license is None


def test_sections_merge_children_and_preserve_exact_source_lines() -> None:
    text = (FIXTURES / "permissive.md").read_text()
    result = inspect(text)
    assert codes(result) == ["usage_context", "no_supported_indicators"]
    evidence = result.findings[0].evidence
    assert (evidence.line_start, evidence.line_end) == (6, 11)
    assert evidence.excerpt == "## Intended use\nThis model embeds text for retrieval.\n\n### Limitations\nPerformance varies by language.\n\n"
    assert result.document_sha256 == hashlib.sha256(text.encode()).hexdigest()


def test_indicators_scan_outside_sections_but_ignore_fences_and_headings() -> None:
    result = inspect((FIXTURES / "usage.md").read_text())
    restrictions = [f for f in result.findings if f.code == "potential_restriction"]
    assert [(f.evidence.line_start, f.evidence.line_end) for f in restrictions] == [(7, 7), (10, 10), (22, 23)]
    assert "commercial use is not permitted" in restrictions[0].message
    assert "may not" in restrictions[1].message
    assert "research only" in restrictions[2].message
    assert restrictions[2].evidence.excerpt == "Research\nonly testing is discussed here.\n"
    assert "no_supported_indicators" not in codes(result)
    contexts = [f.evidence for f in result.findings if f.code == "usage_context"]
    assert [(e.line_start, e.line_end) for e in contexts] == [(9, 18), (20, 20)]
    assert result.normalized_license == "MIT"


@pytest.mark.parametrize("indicator", [
    "non-commercial", "noncommercial", "research-only", "research only", "research purposes only",
    "commercial use is prohibited", "commercial use is not permitted", "may not", "must not",
    "prohibited uses", "restricted to",
])
def test_each_supported_indicator_is_a_review_aid(indicator: str) -> None:
    result = inspect(f"---\nlicense: MIT\n---\n\nWe mention {indicator.upper()} in synthetic prose.\n")
    findings = [f for f in result.findings if f.code == "potential_restriction"]
    assert len(findings) == 1
    assert indicator in findings[0].message
    assert findings[0].evidence.line_start == 5


def test_heading_alone_and_near_words_are_not_restriction_findings() -> None:
    result = inspect("---\nlicense: MIT\n---\n# Prohibited uses\n\nLicensed implementation.\n")
    assert codes(result) == ["usage_context", "no_supported_indicators"]


def test_terms_resolve_to_blob_location_and_are_explicitly_unread() -> None:
    result = inspect((FIXTURES / "custom.md").read_text())
    terms = [f for f in result.findings if f.code == "referenced_terms_unread"]
    assert len(terms) == 3  # metadata plus both ordinary section links
    assert "https://huggingface.co/test/model/blob/main/LICENSE" in terms[0].message
    assert terms[0].evidence.excerpt == "license_link: LICENSE\n"
    assert "https://example.org/use" in terms[2].message
    assert all("not fetched or assessed" in f.message for f in terms)
    assert all("image.png" not in f.message and "#license" not in f.message for f in terms)


def test_duplicate_fixture_metadata_is_invalid_without_silently_selecting_license() -> None:
    result = inspect((FIXTURES / "invalid.md").read_text())
    assert result.normalized_license is None
    assert codes(result) == ["invalid_metadata", "usage_context", "no_supported_indicators"]


def test_supported_license_retains_metadata_evidence_for_policy_conflicts() -> None:
    result = inspect("---\n# Synthetic multiline metadata\nlicense: >-\n  apache-2.0\n---\n# Body\n")
    assert hasattr(result, "license_evidence"), "Policy conflicts require actual metadata provenance"
    assert result.license_evidence.excerpt == "license: >-\n  apache-2.0\n"
    assert (result.license_evidence.line_start, result.license_evidence.line_end) == (3, 4)


@pytest.mark.parametrize("title", [
    "License", "LICENSING", "Usage   Restrictions", "Use restrictions", "Restrictions", "Acceptable use",
    "Prohibited uses", "Intended use", "Intended uses", "Out-of-scope use", "Out-of-scope uses",
    "Misuse", "Limitations", "Bias, Risks, and Limitations",
])
def test_declared_section_titles_collect_technical_context(title: str) -> None:
    result = inspect(f"---\nlicense: MIT\n---\n## {title} ##\nTechnical details.\n## Other\nOutside.\n")
    assert codes(result) == ["usage_context", "no_supported_indicators"]
    assert result.findings[0].evidence.excerpt == f"## {title} ##\nTechnical details.\n"


def test_license_links_in_child_headings_are_preserved_but_code_links_are_ignored() -> None:
    text = "---\nlicense: MIT\n---\n## License\n### Read [terms](LICENSE)\n\n```\n[example](ignored.md)\n```\n"
    result = inspect(text)
    links = [f for f in result.findings if f.code == "referenced_terms_unread"]
    assert len(links) == 1
    assert "https://huggingface.co/test/model/blob/main/LICENSE" in links[0].message
    assert links[0].evidence.excerpt == "### Read [terms](LICENSE)\n"
    assert links[0].evidence.line_start == links[0].evidence.line_end == 5


def test_custom_name_classification_quotes_both_supporting_metadata_lines() -> None:
    result = inspect("---\nlicense: unfamiliar\nlicense_name: Synthetic terms\n---\n# Body\n")
    finding = next(f for f in result.findings if f.code == "custom_license")
    assert finding.evidence.excerpt == "license: unfamiliar\nlicense_name: Synthetic terms\n"


def test_deep_yaml_metadata_recursion_limit_becomes_a_finding() -> None:
    result = inspect("---\nlicense: " + "[" * 1600 + "mit" + "]" * 1600 + "\n---\n## Limitations\nContext.\n")
    assert result.status == "inspected"
    assert codes(result) == ["invalid_metadata", "usage_context", "no_supported_indicators"]


def test_merged_duplicate_keys_are_not_silently_selected() -> None:
    result = inspect("---\nbase: &base\n  license: mit\n<<: *base\nlicense: apache-2.0\n---\n# Body\n")
    assert result.normalized_license is None
    assert codes(result) == ["invalid_metadata", "no_supported_indicators"]


@pytest.mark.parametrize("metadata", ["license: bad\x00value", "license: " + "9" * 5000], ids=["invalid-character", "oversized-number"])
def test_metadata_reader_and_scalar_conversion_errors_are_findings(metadata: str) -> None:
    result = inspect(f"---\n{metadata}\n---\n## Limitations\nContext survives.\n")
    assert result.status == "inspected"
    assert codes(result) == ["invalid_metadata", "usage_context", "no_supported_indicators"]
