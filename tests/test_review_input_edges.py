"""Untrusted input must obey the installed CLI's actionable-error contract."""

import json
import subprocess
from pathlib import Path
from typing import Any

import pytest


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
