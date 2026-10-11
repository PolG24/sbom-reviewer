"""Synthetic machine evidence shared by saved-review behavioral tests."""

import pytest

from sbom_reviewer.models import ReviewResult


@pytest.fixture
def machine_review() -> ReviewResult:
    return ReviewResult.model_validate({
        "policy_version": "synthetic-1",
        "summary": {"total": 3, "allow": 1, "needs_review": 1, "reject": 1},
        "results": [
            {
                "component_id": f"#/components/{index}", "bom_ref": None,
                "name": "same name", "version": None, "type": "library",
                "declared_licenses": licenses, "decision": outcome,
                "reason": reason,
                "sources": [{"url": None, "kind": "sbom-declaration",
                             "pointer": f"#/components/{index}/licenses"}],
                "model_assessment": assessment,
            }
            for index, (licenses, outcome, reason, assessment) in enumerate([
                (["MIT"], "Allow", "Declared MIT matches policy.", None),
                ([], "Needs review", "License evidence is missing.", {
                    "status": "inspected", "document_url": "https://example.org/card",
                    "document_sha256": "a" * 64, "card_license": "mit",
                    "normalized_license": "MIT", "license_policy_decision": "Allow",
                    "license_evidence": {"document_url": "https://example.org/card",
                        "line_start": 2, "line_end": 2, "excerpt": "license: mit"},
                    "findings": [{"code": "referenced_terms_unread",
                        "message": "Linked terms were not fetched or assessed.",
                        "evidence": {"document_url": "https://example.org/card",
                            "line_start": 5, "line_end": 6,
                            "excerpt": "# License\n[Terms](https://example.org/terms)"}}],
                }),
                (["AGPL-3.0-only"], "Reject", "Declared license is rejected.", None),
            ])
        ],
    })
