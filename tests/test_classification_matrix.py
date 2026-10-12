"""Independent review cases exercise the adapter-to-classifier public boundary.

Add a case to fixtures/classification_cases.json to extend the matrix. Expected
decisions and declarations are literal, independent of production helpers.
"""

import json
import socket
from pathlib import Path
from typing import Any, TypedDict

import pytest

from sbom_reviewer.models import Component, Policy
from sbom_reviewer.policy import classify_component, classify_components, load_policy
from sbom_reviewer.sbom import load_sbom


FIXTURES = Path(__file__).parent / "fixtures"


class ClassificationCase(TypedDict):
    id: str
    component: dict[str, Any]
    decision: str
    declared_licenses: list[str]
    reason_parts: list[str]


CASES: list[ClassificationCase] = json.loads(
    (FIXTURES / "classification_cases.json").read_text(encoding="utf-8")
)


@pytest.fixture(scope="module")
def matrix_inputs(tmp_path_factory: pytest.TempPathFactory) -> tuple[list[Component], Policy]:
    path = tmp_path_factory.mktemp("classification-matrix") / "bom.json"
    path.write_text(json.dumps({
        "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
        "components": [case["component"] for case in CASES],
    }), encoding="utf-8")
    return load_sbom(path), load_policy(FIXTURES / "classification_policy.json")


@pytest.mark.parametrize("index, case", list(enumerate(CASES)), ids=[case["id"] for case in CASES])
def test_component_classification_matrix(
    index: int,
    case: ClassificationCase,
    matrix_inputs: tuple[list[Component], Policy],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Catches policy bypass, ambiguity shortcuts, inference from source/name,
    # model overrides of rejection, and loss of provenance in returned findings.
    def deny_network(*args: object, **kwargs: object) -> None:
        raise AssertionError("Classification must not access the network")

    monkeypatch.setattr(socket.socket, "connect", deny_network)
    components, policy = matrix_inputs
    component = components[index]
    before_component = component.model_dump()
    before_policy = policy.model_dump()
    result = classify_component(component, policy)

    assert result.decision == case["decision"]
    assert result.declared_licenses == case["declared_licenses"]
    assert all(part in result.reason for part in case["reason_parts"]), result.reason
    assert result.component_id == f"#/components/{index}"
    assert result.bom_ref == case["component"].get("bom-ref")
    assert result.name == case["component"]["name"]
    assert result.version == case["component"].get("version")
    assert result.type == case["component"]["type"]
    assert result.sources == component.sources
    assert result.sources
    assert component.model_dump() == before_component
    assert policy.model_dump() == before_policy
    assert classify_component(component, policy).model_dump() == result.model_dump()


def test_matrix_summary_counts_final_model_decisions(
    matrix_inputs: tuple[list[Component], Policy],
) -> None:
    # Catches counting the underlying license finding before model deferral.
    components, policy = matrix_inputs
    result = classify_components(components, policy)
    assert [finding.decision for finding in result.results] == [case["decision"] for case in CASES]
    assert result.summary.total == len(CASES)
    for field, decision in (("allow", "Allow"), ("needs_review", "Needs review"), ("reject", "Reject")):
        assert getattr(result.summary, field) == sum(case["decision"] == decision for case in CASES)


def test_same_component_tracks_policy_changes(matrix_inputs: tuple[list[Component], Policy]) -> None:
    # Catches caching a decision without the policy or hard-coding sample rules.
    components, alternate_policy = matrix_inputs
    component = next(component for component in components if component.name == "agpl-single-id")
    reject_policy = Policy(version="reject-agpl", allowed=[], review=[], rejected=["AGPL-3.0-only"])
    empty_policy = Policy(version="empty", allowed=[], review=[], rejected=[])
    assert classify_component(component, alternate_policy).decision == "Allow"
    rejected = classify_component(component, reject_policy)
    assert rejected.decision == "Reject"
    assert "reject-agpl" in rejected.reason
    assert classify_component(component, empty_policy).decision == "Needs review"
    assert classify_component(component, alternate_policy).decision == "Allow"
