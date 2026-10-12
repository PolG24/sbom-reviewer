"""Untrusted input must obey the installed CLI's actionable-error contract."""

import json
import subprocess
from pathlib import Path
from typing import Any

import pytest


@pytest.mark.parametrize("target", ["SBOM", "policy"])
@pytest.mark.parametrize("constant", ["NaN", "Infinity", "-Infinity"])
def test_non_json_constants_are_rejected_at_the_parse_boundary(tmp_path: Path, target: str, constant: str) -> None:
    # Reject these tokens even where the schema would otherwise produce an error;
    # the policy and SBOM loaders must use the same strict JSON contract.
    from sbom_reviewer.policy import load_policy
    from sbom_reviewer.sbom import load_sbom

    path = tmp_path / "non-json.json"
    text = (
        '{"bomFormat":"CycloneDX","specVersion":"1.6","components":[],"version":' + constant + '}'
        if target == "SBOM" else
        '{"version":"test","allowed":[' + constant + '],"review":[],"rejected":[]}'
    )
    path.write_text(text, encoding="utf-8")
    loader = load_sbom if target == "SBOM" else load_policy
    with pytest.raises(ValueError, match="Invalid JSON numeric constant"):
        loader(path)


def test_numeric_constant_names_inside_strings_remain_declarations(tmp_path: Path) -> None:
    from sbom_reviewer.policy import classify_components, load_policy
    from sbom_reviewer.sbom import load_sbom

    sbom = tmp_path / "quoted.json"
    sbom.write_text(json.dumps({
        "bomFormat": "CycloneDX", "specVersion": "1.6", "components": [{
            "type": "library", "name": "NaN Infinity -Infinity",
            "licenses": [{"license": {"name": "NaN Infinity -Infinity"}}],
        }],
    }), encoding="utf-8")
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps({"version": "NaN", "allowed": ["Infinity"], "review": [], "rejected": []}), encoding="utf-8")
    result = classify_components(load_sbom(sbom), load_policy(policy))
    assert result.policy_version == "NaN"
    assert result.results[0].name == "NaN Infinity -Infinity"
    assert result.results[0].declared_licenses == ["NaN Infinity -Infinity"]
    assert result.results[0].decision == "Needs review"


@pytest.mark.parametrize("constant", ["NaN", "Infinity", "-Infinity"])
def test_non_json_numeric_constants_are_input_errors(tmp_path: Path, constant: str) -> None:
    # Catches Python's permissive JSON decoder passing invalid JSON numbers into
    # deserialization, where NaN currently leaks decimal.InvalidOperation.
    sbom = tmp_path / "non-json-number.json"
    sbom.write_text(
        '{"bomFormat":"CycloneDX","specVersion":"1.6","components":['
        '{"type":"library","name":"untrusted","evidence":{"identity":'
        '{"field":"name","confidence":' + constant + '}}}]}',
        encoding="utf-8",
    )
    policy = Path(__file__).parent / "fixtures" / "classification_policy.json"
    result = subprocess.run(
        ["sbom-reviewer", "review", str(sbom), "--policy", str(policy)],
        check=False, capture_output=True, text=True,
    )
    assert result.returncode == 2, "\n".join(result.stderr.splitlines()[-8:])
    assert result.stdout == ""
    assert "Cannot review SBOM" in result.stderr
    assert str(sbom) in result.stderr
    assert "Traceback" not in result.stderr


def test_deep_inventory_completes_or_reports_actionable_input_limit(tmp_path: Path) -> None:
    # Catches uncontrolled recursion in parsing/validation/traversal of untrusted
    # input. A documented depth limit is acceptable; a raw traceback is not.
    depth = 200
    component: dict[str, Any] = {"type": "library", "name": "leaf"}
    for index in range(depth):
        component = {"type": "library", "name": f"parent-{index}", "components": [component]}
    sbom = tmp_path / "deep-inventory.json"
    sbom.write_text(json.dumps({
        "bomFormat": "CycloneDX", "specVersion": "1.6", "components": [component],
    }), encoding="utf-8")
    policy = Path(__file__).parent / "fixtures" / "classification_policy.json"
    result = subprocess.run(
        ["sbom-reviewer", "review", str(sbom), "--policy", str(policy)],
        check=False, capture_output=True, text=True,
    )
    assert result.returncode in {0, 2}, "\n".join(result.stderr.splitlines()[-8:])
    assert "Traceback" not in result.stderr
    if result.returncode == 0:
        assert result.stderr == ""
        review = json.loads(result.stdout)
        assert len(review["results"]) == depth + 1
        assert review["summary"] == {"total": depth + 1, "allow": 0, "needs_review": depth + 1, "reject": 0}
    else:
        assert result.stdout == ""
        assert "Cannot review SBOM" in result.stderr
        assert str(sbom) in result.stderr
        assert any(word in result.stderr.lower() for word in ("depth", "nesting", "nested", "recursion"))
