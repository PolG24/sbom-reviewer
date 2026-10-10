"""The adapter validates untrusted input and preserves original provenance."""

import json
import socket
from pathlib import Path

import pytest


def write_bom(tmp_path: Path, **fields: object) -> Path:
    path = tmp_path / "bom.json"
    path.write_text(json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1} | fields))
    return path


def component(name: str = "same", **fields: object) -> dict:
    return {"type": "library", "name": name} | fields


def test_depth_first_inventory_preserves_locations_and_optional_fields(tmp_path: Path) -> None:
    from sbom_reviewer.sbom import load_sbom

    path = write_bom(
        tmp_path,
        metadata={"component": component("product", **{"bom-ref": "root"}, components=[component("root-child")])},
        components=[
            component(**{"bom-ref": "one"}, version="1", components=[
                component(components=[component("grandchild")]), component("second-child"),
            ]),
            component(**{"bom-ref": "two"}, version="1"),
        ],
        services=[{"name": "ignored-service"}],
        dependencies=[{"ref": "one", "dependsOn": ["two"]}],
    )
    result = load_sbom(path)
    assert [c.component_id for c in result] == [
        "#/metadata/component", "#/metadata/component/components/0",
        "#/components/0", "#/components/0/components/0",
        "#/components/0/components/0/components/0", "#/components/0/components/1",
        "#/components/1",
    ]
    assert [c.name for c in result] == ["product", "root-child", "same", "same", "grandchild", "second-child", "same"]
    assert [c.version for c in result] == [None, None, "1", None, None, None, "1"]
    assert [c.bom_ref for c in result] == ["root", None, "one", None, None, None, "two"]
    assert load_sbom(path) == result


@pytest.mark.parametrize("fields", [{}, {"components": []}, {"metadata": {}}])
def test_empty_inventory_is_valid(tmp_path: Path, fields: dict) -> None:
    from sbom_reviewer.sbom import load_sbom

    assert load_sbom(write_bom(tmp_path, **fields)) == []


@pytest.mark.parametrize(
    "fields",
    [
        {"components": [component(**{"bom-ref": "duplicate"}), component(**{"bom-ref": "duplicate"})]},
        {"metadata": {"component": component(**{"bom-ref": "duplicate"})},
         "components": [component(components=[component(**{"bom-ref": "duplicate"})])]},
    ],
)
def test_duplicate_explicit_bom_refs_are_input_errors(tmp_path: Path, fields: dict) -> None:
    from sbom_reviewer.sbom import load_sbom

    with pytest.raises(ValueError, match=r"[Dd]uplicate.*bom-ref.*duplicate.*#/"):
        load_sbom(write_bom(tmp_path, **fields))


def test_sources_and_all_license_declarations_are_preserved(tmp_path: Path) -> None:
    from sbom_reviewer.sbom import load_sbom

    path = write_bom(tmp_path, components=[
        component(licenses=[
            {"license": {"id": "MIT", "url": "https://example.org/MIT"}},
            {"license": {"name": "Custom", "url": "http://example.org/custom"}},
        ], externalReferences=[
            {"type": "license", "url": "https://example.org/terms"},
            {"type": "model-card", "url": "https://example.org/card"},
            {"type": "vcs", "url": "https://example.org/code"},
        ]),
        component(licenses=[{"license": {"id": "Apache-2.0"}}]),
        component(licenses=[{"expression": "MIT"}]),
        component(licenses=[{"expression": "MIT OR Apache-2.0"}]),
        component(licenses=[{"license": {"name": "MIT"}}]),
        component(),
    ])
    result = load_sbom(path)
    assert [(d.kind, d.value, d.pointer) for d in result[0].licenses] == [
        ("spdx", "MIT", "#/components/0/licenses/0/license/id"),
        ("name", "Custom", "#/components/0/licenses/1/license/name"),
    ]
    assert [source.model_dump() for source in result[0].sources] == [
        {"url": "https://example.org/MIT", "kind": "license", "pointer": "#/components/0/licenses/0/license/url"},
        {"url": "http://example.org/custom", "kind": "license", "pointer": "#/components/0/licenses/1/license/url"},
        {"url": "https://example.org/terms", "kind": "license", "pointer": "#/components/0/externalReferences/0/url"},
        {"url": "https://example.org/card", "kind": "model-card", "pointer": "#/components/0/externalReferences/1/url"},
    ]
    assert result[1].sources[0].model_dump() == {
        "url": "https://spdx.org/licenses/Apache-2.0.html", "kind": "license",
        "pointer": "#/components/1/licenses/0/license/id",
    }
    assert result[2].sources[0].url == "https://spdx.org/licenses/MIT.html"
    assert result[2].sources[0].pointer == "#/components/2/licenses/0/expression"
    assert result[3].licenses[0].value == "MIT OR Apache-2.0"
    assert result[3].sources[0].model_dump() == {
        "url": None, "kind": "sbom-declaration", "pointer": "#/components/3/licenses/0/expression",
    }
    assert result[4].sources[0].url is None  # A name equal to an SPDX ID is still custom.
    assert result[5].sources[0].model_dump() == {
        "url": None, "kind": "sbom-declaration", "pointer": "#/components/5",
    }


@pytest.mark.parametrize("url", ["file:///tmp/license", "javascript:alert(1)", "ftp://example.org/license", "relative.txt"])
def test_non_http_references_do_not_become_actionable_urls(tmp_path: Path, url: str) -> None:
    from sbom_reviewer.sbom import load_sbom

    path = write_bom(tmp_path, components=[component(
        licenses=[{"license": {"name": "Custom", "url": url}}],
        externalReferences=[{"type": "model-card", "url": url}],
    )])
    sources = load_sbom(path)[0].sources
    assert [s.url for s in sources] == [None, None, None]
    assert [s.kind for s in sources] == ["license", "model-card", "sbom-declaration"]
    assert sources[-1].pointer == "#/components/0/licenses/0/license/name"


@pytest.mark.parametrize(
    "fields, message",
    [
        ({"bomFormat": "SPDX"}, "CycloneDX"),
        ({"specVersion": "1.5"}, "1.6"),
        ({"specVersion": 1.6}, "1.6"),
        ({"components": {}}, "schema"),
        ({"components": [{"name": "no-type"}]}, "schema"),
        ({"components": [{"type": "library"}]}, "schema"),
        ({"components": [component(licenses=[{"license": {"id": "LicenseRef-Custom"}}])]}, "schema"),
        ({"components": [component(licenses=[{"license": {"id": "made-up"}}])]}, "schema"),
        ({"components": [component(licenses=[{"license": {"id": "MIT", "name": "MIT"}}])]}, "schema"),
        ({"components": [component(licenses=[{}])]}, "schema"),
        ({"components": [component(licenses="MIT")]}, "schema"),
        ({"components": [component(licenses=[{"expression": "MIT"}, {"expression": "Apache-2.0"}])]}, "schema"),
    ],
)
def test_unsupported_and_schema_invalid_input_is_rejected(tmp_path: Path, fields: dict, message: str) -> None:
    from sbom_reviewer.sbom import load_sbom

    with pytest.raises(ValueError, match=message):
        load_sbom(write_bom(tmp_path, **fields))


@pytest.mark.parametrize("text", ["{", "[]", "null", '{"bomFormat":"CycloneDX"}', "not JSON"])
def test_invalid_documents_are_input_errors(tmp_path: Path, text: str) -> None:
    from sbom_reviewer.sbom import load_sbom

    path = tmp_path / "bad.json"
    path.write_text(text)
    with pytest.raises(ValueError):
        load_sbom(path)


def test_validation_and_deserialization_never_connect_to_network(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from sbom_reviewer.sbom import load_sbom

    def deny_network(*args: object, **kwargs: object) -> None:
        raise AssertionError("SBOM review must never access the network")

    monkeypatch.setattr(socket.socket, "connect", deny_network)
    path = write_bom(tmp_path, **{"$schema": "https://example.org/untrusted-schema"}, components=[component(
        licenses=[{"license": {"id": "MIT"}}],
        externalReferences=[{"type": "model-card", "url": "https://example.org/never-fetched"}],
    )])
    assert load_sbom(path)[0].licenses[0].value == "MIT"


def test_missing_validation_support_is_an_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from cyclonedx.exception import MissingOptionalDependencyException
    from cyclonedx.validation.json import JsonStrictValidator
    from sbom_reviewer.sbom import load_sbom

    def unavailable(*args: object, **kwargs: object) -> None:
        raise MissingOptionalDependencyException("validation dependency missing")

    monkeypatch.setattr(JsonStrictValidator, "validate_str", unavailable)
    with pytest.raises(ValueError, match="json-validation"):
        load_sbom(write_bom(tmp_path))


def test_unreadable_file_is_an_input_error(tmp_path: Path) -> None:
    from sbom_reviewer.sbom import load_sbom

    with pytest.raises(OSError):
        load_sbom(tmp_path / "missing.json")
