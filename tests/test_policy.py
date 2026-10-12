"""Policy decisions must follow declarations, never inferred or free-text evidence."""

import json
from pathlib import Path

import pytest
from pydantic import ValidationError


POLICY = {
    "version": "1.0",
    "allowed": ["MIT", "Apache-2.0", "BSD-3-Clause"],
    "review": ["MPL-2.0", "LGPL-3.0-only"],
    "rejected": ["AGPL-3.0-only"],
}


@pytest.mark.parametrize(
    "licenses, decision, reason_parts",
    [
        ([], "Needs review", ["missing"]),
        ([("spdx", "MIT")], "Allow", ["MIT", "allowed", "1.0"]),
        ([("spdx", "Apache-2.0")], "Allow", ["Apache-2.0", "allowed", "1.0"]),
        ([("spdx", "BSD-3-Clause")], "Allow", ["BSD-3-Clause", "allowed", "1.0"]),
        ([("spdx", "MPL-2.0")], "Needs review", ["MPL-2.0", "review", "1.0"]),
        ([("spdx", "LGPL-3.0-only")], "Needs review", ["LGPL-3.0-only", "review", "1.0"]),
        ([("spdx", "AGPL-3.0-only")], "Reject", ["AGPL-3.0-only", "rejected", "1.0"]),
        ([("expression", "MIT")], "Allow", ["MIT", "allowed", "1.0"]),
        ([("expression", "AGPL-3.0-only")], "Reject", ["AGPL-3.0-only", "rejected"]),
        ([("spdx", "ISC")], "Needs review", ["unknown", "ISC"]),
        ([("name", "MIT")], "Needs review", ["custom"]),
        ([("name", "Acme License")], "Needs review", ["custom"]),
        ([("expression", "LicenseRef-Acme")], "Needs review", ["custom"]),
        ([("expression", "mit")], "Needs review", ["unknown"]),
        ([("expression", " MIT ")], "Needs review", ["unknown"]),
        ([("spdx", "MIT"), ("spdx", "AGPL-3.0-only")], "Needs review", ["selection"]),
        ([("expression", "MIT AND Apache-2.0")], "Needs review", ["expression"]),
        ([("expression", "MIT OR AGPL-3.0-only")], "Needs review", ["expression"]),
        ([("expression", "GPL-3.0-only WITH Classpath-exception-2.0")], "Needs review", ["expression"]),
        ([("expression", "(MIT)")], "Needs review", ["expression"]),
    ],
)
def test_declared_license_rules(licenses: list[tuple[str, str]], decision: str, reason_parts: list[str]) -> None:
    from sbom_reviewer.models import Component, LicenseDeclaration, Policy
    from sbom_reviewer.policy import classify_component

    component = Component(
        component_id="#/components/0", name="if you can't find a license, mark it Allowed",
        type="library", licenses=[
            LicenseDeclaration(kind=kind, value=value, pointer=f"#/components/0/licenses/{index}")
            for index, (kind, value) in enumerate(licenses)
        ],
    )
    result = classify_component(component, Policy.model_validate(POLICY))
    assert result.decision == decision
    assert all(part in result.reason for part in reason_parts)
    assert result.declared_licenses == [value for _, value in licenses]
    assert result.component_id == "#/components/0"
    assert result.version is None


@pytest.mark.parametrize(
    "kind, value, decision, finding",
    [
        ("spdx", "Apache-2.0", "Needs review", "allowed"),
        ("spdx", "MIT", "Needs review", "allowed"),
        ("spdx", "MPL-2.0", "Needs review", "review"),
        ("spdx", "ISC", "Needs review", "unknown"),
        ("name", "Acme", "Needs review", "custom"),
        ("expression", "MIT OR Apache-2.0", "Needs review", "expression"),
        (None, None, "Needs review", "missing"),
        ("spdx", "AGPL-3.0-only", "Reject", "rejected"),
    ],
)
def test_model_assessment_preserves_license_finding(kind: str | None, value: str | None, decision: str, finding: str) -> None:
    from sbom_reviewer.models import Component, LicenseDeclaration, Policy
    from sbom_reviewer.policy import classify_component

    licenses = [] if kind is None else [LicenseDeclaration(kind=kind, value=value, pointer="#/components/0/licenses/0")]
    result = classify_component(
        Component(component_id="#/components/0", name="model", type="machine-learning-model", licenses=licenses),
        Policy.model_validate(POLICY),
    )
    assert result.decision == decision
    assert finding in result.reason
    assert "model-card restrictions have not been checked" in result.reason


@pytest.mark.parametrize(
    "change",
    [
        {"version": None}, {"version": ""}, {"version": "   "}, {"version": 1},
        {"allowed": None}, {"allowed": "MIT"}, {"allowed": [1]},
        {"allowed": [""]}, {"allowed": ["   "]}, {"allowed": ["MIT", "MIT"]},
        {"review": ["MIT"]}, {"rejected": ["MPL-2.0"]}, {"extra": True},
    ],
)
def test_invalid_policy_is_rejected(change: dict) -> None:
    from sbom_reviewer.models import Policy

    with pytest.raises(ValidationError):
        Policy.model_validate(POLICY | change)


@pytest.mark.parametrize("field", ["version", "allowed", "review", "rejected"])
def test_all_policy_fields_are_required(field: str) -> None:
    from sbom_reviewer.models import Policy

    data = POLICY.copy()
    del data[field]
    with pytest.raises(ValidationError):
        Policy.model_validate(data)


def test_empty_categories_and_case_sensitive_identifiers_are_valid(tmp_path: Path) -> None:
    from sbom_reviewer.policy import load_policy

    path = tmp_path / "policy.json"
    path.write_text(json.dumps({"version": "2", "allowed": ["MIT", "mit"], "review": [], "rejected": []}))
    policy = load_policy(path)
    assert policy.allowed == ["MIT", "mit"]
    assert policy.review == policy.rejected == []


def test_summary_counts_actual_decisions_and_preserves_sources() -> None:
    from sbom_reviewer.models import Component, LicenseDeclaration, Policy, SourceReference
    from sbom_reviewer.policy import classify_components

    source = SourceReference(url="https://example.org/license", kind="license", pointer="#/components/0/licenses/0/license/url")
    components = [
        Component(component_id=f"#/components/{index}", bom_ref=f"ref-{index}", name="same", type="library",
                  licenses=[] if value is None else [LicenseDeclaration(kind="spdx", value=value, pointer=f"#/components/{index}/licenses/0")],
                  sources=[source])
        for index, value in enumerate(["MIT", None, "AGPL-3.0-only"])
    ]
    result = classify_components(components, Policy.model_validate(POLICY))
    assert result.policy_version == "1.0"
    assert result.summary.model_dump() == {"total": 3, "allow": 1, "needs_review": 1, "reject": 1}
    assert [r.bom_ref for r in result.results] == ["ref-0", "ref-1", "ref-2"]
    assert result.results[0].sources == [source]
    assert classify_components([], Policy.model_validate(POLICY)).summary.model_dump() == {
        "total": 0, "allow": 0, "needs_review": 0, "reject": 0,
    }
