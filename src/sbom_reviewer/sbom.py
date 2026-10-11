"""Validate CycloneDX 1.6 locally and adapt the original declarations."""

from collections.abc import Iterator
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from cyclonedx.exception import CycloneDxException, MissingOptionalDependencyException
from cyclonedx.model.bom import Bom
from cyclonedx.schema import SchemaVersion
from cyclonedx.spdx import is_supported_id
from cyclonedx.validation.json import JsonStrictValidator

from sbom_reviewer.json_input import parse_json
from sbom_reviewer.models import Component, LicenseDeclaration, SourceReference


def walk_components(document: dict[str, Any]) -> Iterator[tuple[str, dict[str, Any]]]:
    """Visit only reviewable inventory, in original depth-first order."""
    def visit(raw: Any, pointer: str) -> Iterator[tuple[str, dict[str, Any]]]:
        if not isinstance(raw, dict):
            return  # The schema validator reports malformed inventory.
        yield pointer, raw
        children = raw.get("components", [])
        if isinstance(children, list):
            for index, child in enumerate(children):
                yield from visit(child, f"{pointer}/components/{index}")

    metadata = document.get("metadata", {})
    if isinstance(metadata, dict) and "component" in metadata:
        yield from visit(metadata["component"], "#/metadata/component")
    components = document.get("components", [])
    if isinstance(components, list):
        for index, raw in enumerate(components):
            yield from visit(raw, f"#/components/{index}")


def http_url(value: str) -> str | None:
    """Retain HTTP(S) references as supplied; never open them."""
    parsed = urlsplit(value)
    return value if parsed.scheme in {"http", "https"} and parsed.netloc else None


def normalize_component(raw: dict[str, Any], pointer: str) -> Component:
    declarations: list[LicenseDeclaration] = []
    sources: list[SourceReference] = []
    for index, entry in enumerate(raw.get("licenses", [])):
        entry_pointer = f"{pointer}/licenses/{index}"
        if "expression" in entry:
            kind, value = "expression", entry["expression"]
            declaration_pointer = f"{entry_pointer}/expression"
            license_data = {}
        else:
            license_data = entry["license"]
            key = "id" if "id" in license_data else "name"
            kind, value = ("spdx" if key == "id" else "name"), license_data[key]
            declaration_pointer = f"{entry_pointer}/license/{key}"
        declarations.append(LicenseDeclaration(kind=kind, value=value, pointer=declaration_pointer))
        if "url" in license_data:
            sources.append(SourceReference(
                url=http_url(license_data["url"]), kind="license", pointer=f"{entry_pointer}/license/url",
            ))
        elif kind != "name" and is_supported_id(value):
            sources.append(SourceReference(
                url=f"https://spdx.org/licenses/{value}.html", kind="license", pointer=declaration_pointer,
            ))

    for index, reference in enumerate(raw.get("externalReferences", [])):
        if reference["type"] in {"license", "model-card"}:
            sources.append(SourceReference(
                url=http_url(reference["url"]), kind=reference["type"],
                pointer=f"{pointer}/externalReferences/{index}/url",
            ))
    if not any(source.url is not None for source in sources):
        evidence_pointers = [declaration.pointer for declaration in declarations] or [pointer]
        sources.extend(SourceReference(url=None, kind="sbom-declaration", pointer=p) for p in evidence_pointers)
    return Component(
        component_id=pointer, bom_ref=raw.get("bom-ref"), name=raw["name"],
        version=raw.get("version"), type=raw["type"], licenses=declarations, sources=sources,
    )


def load_sbom(path: Path) -> list[Component]:
    text = path.read_text(encoding="utf-8")
    document = parse_json(text)
    if not isinstance(document, dict) or document.get("bomFormat") != "CycloneDX":
        raise ValueError("Unsupported SBOM format: provide a CycloneDX JSON 1.6 object.")
    if document.get("specVersion") != "1.6":
        raise ValueError("Unsupported SBOM version: only CycloneDX JSON 1.6 is supported.")
    try:
        error = JsonStrictValidator(SchemaVersion.V1_6).validate_str(text)
    except MissingOptionalDependencyException as exc:
        raise ValueError("Schema validation unavailable: install cyclonedx-python-lib[json-validation].") from exc
    inventory = list(walk_components(document))
    references: dict[str, str] = {}
    for pointer, raw in inventory:
        if isinstance(raw.get("bom-ref"), str):
            reference = raw["bom-ref"]
            if reference in references:
                raise ValueError(f"Duplicate component bom-ref {reference!r} at {references[reference]} and {pointer}.")
            references[reference] = pointer
    if error is not None:
        location = "/".join(str(part) for part in error.data.absolute_path)
        raise ValueError(f"Invalid CycloneDX 1.6 schema at #/{location}: {error.data.message}")
    try:
        bom = Bom.from_json(data=document)
    except (CycloneDxException, ValueError, TypeError) as exc:
        raise ValueError(f"Unable to deserialize CycloneDX SBOM: {exc}") from exc
    if bom is None:
        raise ValueError("Unable to deserialize CycloneDX SBOM: no BOM model returned.")

    # Library sets can sort/collapse declarations and generate identities. The
    # validated raw document remains authoritative for these application fields.
    return [normalize_component(raw, pointer) for pointer, raw in inventory]
