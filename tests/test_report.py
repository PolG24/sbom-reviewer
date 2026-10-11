"""Readable complete reports with untrusted text and safe links."""

from html.parser import HTMLParser
from pathlib import Path

import pytest

from sbom_reviewer.models import ReviewResult
from sbom_reviewer.report import render_report
from sbom_reviewer.storage import load_review, record_decision, save_review


class ParsedReport(HTMLParser):
    def __init__(self, document: str) -> None:
        super().__init__()
        self.tags: list[str] = []
        self.attributes: list[tuple[str, str | None]] = []
        self.text: list[str] = []
        self.tables: list[list[str]] = []
        self.in_table = False
        self.feed(document)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags.append(tag)
        self.attributes.extend(attrs)
        if tag == "table":
            self.in_table = True
            self.tables.append([])

    def handle_endtag(self, tag: str) -> None:
        if tag == "table":
            self.in_table = False

    def handle_data(self, data: str) -> None:
        self.text.append(data)
        if self.in_table:
            self.tables[-1].append(data)


def test_report_retains_all_machine_evidence_pending_states_and_superseded_history(tmp_path: Path, machine_review: ReviewResult) -> None:
    path = tmp_path / "review.sqlite"
    save_review(path, machine_review)
    first = record_decision(path, "#/components/2", override="Allow", reviewer="First Legal", reason="Illustrative exception")
    second = record_decision(path, "#/components/2", confirm=True, reviewer="Second Legal", reason="Return to original policy")
    saved = load_review(path)
    document = render_report(saved)
    parsed = ParsedReport(document)
    text = " ".join(parsed.text)
    assert document.startswith("<!DOCTYPE html>")
    assert "style" in parsed.tags and "script" not in parsed.tags
    assert [value for key, value in parsed.attributes if key == "data-component-id"] == [
        "#/components/0", "#/components/1", "#/components/2"]
    for expected in ["synthetic-1", saved.saved_at.isoformat(), "MIT", "AGPL-3.0-only",
                     "Machine recommendation", "Human decision", "Pending human review",
                     "License evidence is missing.", "inspected", "a" * 64, "license: mit",
                     "referenced_terms_unread", "Linked terms were not fetched or assessed.",
                     "# License\n[Terms](https://example.org/terms)", "Lines 5–6",
                     "First Legal", "Illustrative exception", "Second Legal", "Return to original policy",
                     "Complete decision history", first.recorded_at.isoformat(), second.recorded_at.isoformat(),
                     "Original machine counts", "Human-decision counts", "Pending", "Reject"]:
        assert expected in text
    assert text.count("Pending human review") == 2
    assert parsed.tables == [["Total", "Allow", "Needs review", "Reject", "3", "1", "1", "1"],
                             ["Total", "Recorded", "Pending", "Allow", "Needs review", "Reject",
                              "3", "1", "2", "0", "0", "1"]]
    history = text.split("Complete decision history", 1)[1]
    assert history.index("Illustrative exception") < history.index("Return to original policy")
    assert render_report(saved) == document


@pytest.mark.parametrize("url,clickable", [
    ("https://example.org/terms?quote=\"&x=1", True), ("http://example.org/license", True),
    ("javascript:alert(1)", False), ("data:text/html,<script>alert(1)</script>", False),
    ("file:///etc/passwd", False), ("//example.org/terms", False),
    ("https:///missing-host", False), ("https://example.org:bad/terms", False),
    ("https://example.org/\nmalicious", False), ("https://[broken", False),
])
def test_untrusted_text_never_becomes_markup_or_unsafe_links(tmp_path: Path, machine_review: ReviewResult, url: str, clickable: bool) -> None:
    attack = '<script>alert("owned")</script><img src=x onerror=alert(1)>'
    machine_review.policy_version = attack
    component = machine_review.results[1]
    component.name = component.reason = component.type = component.version = component.bom_ref = attack
    component.component_id = attack
    component.declared_licenses = [attack]
    component.sources[0].url = url
    component.sources[0].pointer = attack
    assessment = component.model_assessment
    assessment.document_url = url
    assessment.card_license = assessment.normalized_license = attack
    assessment.license_evidence.document_url = url
    assessment.license_evidence.excerpt = attack
    assessment.findings[0].message = attack
    assessment.findings[0].evidence.excerpt = attack
    assessment.findings[0].evidence.document_url = url
    path = tmp_path / "review.sqlite"
    save_review(path, machine_review)
    record_decision(path, attack, override="Allow", reviewer=attack, reason=attack)
    document = render_report(load_review(path))
    parsed = ParsedReport(document)
    assert attack in " ".join(parsed.text)
    assert "script" not in parsed.tags and "img" not in parsed.tags
    assert not any(key == "src" for key, _ in parsed.attributes)
    assert not any(key.startswith("on") for key, _ in parsed.attributes)
    links = [value for key, value in parsed.attributes if key == "href"]
    assert (url in links) == clickable
    assert all(value.startswith(("http://", "https://")) for value in links)
    assert '&lt;script&gt;' in document


@pytest.mark.parametrize("status", ["unavailable", "unsupported"])
def test_unavailable_evidence_is_distinct_from_inspection(tmp_path: Path, machine_review: ReviewResult, status: str) -> None:
    from sbom_reviewer.models import ModelAssessment, ModelFinding, FindingCode
    machine_review.results[1].model_assessment = ModelAssessment(
        status=status, findings=[ModelFinding(code=FindingCode.UNAVAILABLE_SOURCE,
                                             message="No document was inspected.")])
    path = tmp_path / "review.sqlite"
    save_review(path, machine_review)
    text = " ".join(ParsedReport(render_report(load_review(path))).text)
    assert status in text
    assert "No document was inspected." in text
    assert "Pending human review" in text
