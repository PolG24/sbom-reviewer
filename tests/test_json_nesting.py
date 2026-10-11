"""Limit untrusted nesting before recursive schema validation or deserialization."""

import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

from sbom_reviewer.json_input import parse_json
from sbom_reviewer.sbom import load_sbom


@pytest.mark.parametrize("container", ["array", "object", "mixed"])
def test_documents_at_the_nesting_limit_preserve_their_leaf(container: str) -> None:
    text = '"leaf"'
    for index in range(128):
        text = '[' + text + ']' if container == "array" or (container == "mixed" and index % 2) else '{"child":' + text + '}'
    document = parse_json(text)
    for _ in range(128):
        document = document[0] if isinstance(document, list) else document["child"]
    assert document == "leaf"


@pytest.mark.parametrize("container", ["array", "object", "mixed"])
def test_documents_above_the_nesting_limit_are_rejected(container: str) -> None:
    text = '"leaf"'
    for index in range(129):
        text = '[' + text + ']' if container == "array" or (container == "mixed" and index % 2) else '{"child":' + text + '}'
    with pytest.raises(ValueError, match=r"nesting.*128"):
        parse_json(text)


def test_nesting_characters_inside_strings_are_not_containers() -> None:
    value = '[[{' * 1000 + '\\"' + '}]]' * 1000
    assert parse_json(json.dumps({"value": value})) == {"value": value}


@pytest.mark.parametrize("target", ["SBOM", "policy"])
@pytest.mark.parametrize("depth", [129, 2000, 20000])
def test_excessive_nesting_is_a_cli_input_error(tmp_path: Path, target: str, depth: int) -> None:
    # Construct raw text so the test's own encoder does not hit a recursion limit.
    nested = '[' * depth + '0' + ']' * depth
    sbom = tmp_path / "bom.json"
    policy = tmp_path / "policy.json"
    sbom.write_text('{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}', encoding="utf-8")
    policy.write_text('{"version":"test","allowed":[],"review":[],"rejected":[]}', encoding="utf-8")
    path = sbom if target == "SBOM" else policy
    path.write_text('{"deep":' + nested + '}', encoding="utf-8")
    result = subprocess.run(
        ["sbom-reviewer", "review", str(sbom), "--policy", str(policy)],
        check=False, capture_output=True, text=True,
    )
    assert result.returncode == 2
    assert result.stdout == ""
    assert str(path) in result.stderr
    assert ("Cannot review SBOM" if target == "SBOM" else "Cannot load policy") in result.stderr
    assert "nesting" in result.stderr and "128" in result.stderr
    assert "Traceback" not in result.stderr


@pytest.mark.parametrize("location", ["top-level", "metadata"])
def test_supported_deep_components_are_reviewed_in_full(tmp_path: Path, location: str) -> None:
    # Root object + component array/metadata object + 63 component objects and
    # their 62 child arrays consume 127 nesting levels, below the 128 limit.
    component: dict[str, Any] = {"type": "library", "name": "leaf"}
    for index in range(62):
        component = {"type": "library", "name": f"parent-{index}", "components": [component]}
    inventory = {"components": [component]} if location == "top-level" else {"metadata": {"component": component}}
    path = tmp_path / "deep-valid.json"
    path.write_text(json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6"} | inventory), encoding="utf-8")
    components = load_sbom(path)
    assert len(components) == 63
    assert [c.name for c in components] == [f"parent-{index}" for index in range(61, -1, -1)] + ["leaf"]
    prefix = "#/components/0" if location == "top-level" else "#/metadata/component"
    assert components[-1].component_id == prefix + "/components/0" * 62
