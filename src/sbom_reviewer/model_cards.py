"""Pure extraction of untrusted model-card metadata and review evidence."""

import re
from collections.abc import Iterator
from urllib.parse import urljoin, urlsplit

import yaml
from cyclonedx.spdx import is_supported_id
from yaml.constructor import ConstructorError
from yaml.nodes import MappingNode, Node

from sbom_reviewer.model_card_fetch import FetchedCard
from sbom_reviewer.models import EvidenceExcerpt, FindingCode, ModelAssessment, ModelFinding

ALIASES = {
    "mit": "MIT", "apache-2.0": "Apache-2.0", "bsd-3-clause": "BSD-3-Clause",
    "mpl-2.0": "MPL-2.0", "lgpl-3.0-only": "LGPL-3.0-only",
    "agpl-3.0-only": "AGPL-3.0-only", "cc-by-nc-4.0": "CC-BY-NC-4.0",
    "cc-by-nc-sa-4.0": "CC-BY-NC-SA-4.0",
}
SECTION_TITLES = {
    "license", "licensing", "usage restrictions", "use restrictions", "restrictions",
    "acceptable use", "prohibited uses", "intended use", "intended uses",
    "out-of-scope use", "out-of-scope uses", "misuse", "limitations",
    "bias, risks, and limitations",
}
INDICATORS = re.compile(
    r"\b(?:non-commercial|noncommercial|research-only|research only|research purposes only|"
    r"commercial use is prohibited|commercial use is not permitted|may not|must not|"
    r"prohibited uses|restricted to)\b", re.IGNORECASE,
)
HEADING = re.compile(r"^ {0,3}(#{1,6})(?:[ \t]+(.*)|[ \t]*)$")
LINK = re.compile(r'(?<!!)\[([^\]\n]+)\]\(\s*(<[^>\n]+>|[^\s)]+)(?:\s+["\'][^\n]*?["\'])?\s*\)')


class UniqueSafeLoader(yaml.SafeLoader):
    """SafeLoader with no silent duplicate-key overwrites (including merges)."""

    def construct_mapping(self, node: MappingNode, deep: bool = False) -> dict:
        self.flatten_mapping(node)
        result: dict = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=True)
            try:
                duplicate = key in result
            except TypeError as exc:
                raise ConstructorError(None, None, "Unhashable metadata key", key_node.start_mark) from exc
            if duplicate:
                raise ConstructorError(None, None, "Duplicate metadata key", key_node.start_mark)
            result[key] = self.construct_object(value_node, deep=deep)
        return result


def _evidence(card: FetchedCard, lines: list[str], start: int, end: int) -> EvidenceExcerpt:
    """Convert a zero-based half-open range to inclusive source positions."""
    return EvidenceExcerpt(document_url=card.document_url, line_start=start + 1,
                           line_end=end, excerpt="".join(lines[start:end]))


def _finding(code: FindingCode, message: str, evidence: EvidenceExcerpt | None = None) -> ModelFinding:
    return ModelFinding(code=code, message=message, evidence=evidence)


def _metadata(card: FetchedCard, lines: list[str]) -> tuple[dict[str, str], dict[str, EvidenceExcerpt], list[ModelFinding], int]:
    if not lines or lines[0].strip() != "---":
        return {}, {}, [_finding(FindingCode.MISSING_LICENSE, "Initial YAML front matter and license metadata are missing.")], 0
    end = next((i for i in range(1, len(lines)) if lines[i].strip() == "---"), None)
    if end is None:
        return {}, {}, [_finding(FindingCode.INVALID_METADATA, "YAML front matter is unclosed.", _evidence(card, lines, 0, len(lines)))], 1
    loader: UniqueSafeLoader | None = None
    try:
        loader = UniqueSafeLoader("".join(lines[1:end]))
        node = loader.get_single_node()
        try:
            data = loader.construct_document(node) if node is not None else {}
        except ValueError as exc:
            # Safe scalar constructors can reject invalid dates or huge integers.
            raise ConstructorError(None, None, "Invalid metadata scalar", None) from exc
        if not isinstance(data, dict):
            raise ConstructorError(None, None, "Metadata must be a mapping", None)
        nodes: dict[str, Node] = {key.value: value for key, value in node.value} if isinstance(node, MappingNode) else {}
        evidence = {}
        for key in ("license", "license_name", "license_link"):
            if key in nodes:
                value = nodes[key]
                # Include the key's line and every line of a multiline scalar.
                key_node = next(k for k, v in node.value if k.value == key)
                stop = value.end_mark.line + (1 if value.end_mark.column else 0)
                evidence[key] = _evidence(card, lines, key_node.start_mark.line + 1, max(stop + 1, key_node.start_mark.line + 2))
        values: dict[str, str] = {}
        findings = []
        for key in ("license", "license_name", "license_link"):
            if key not in data:
                continue
            if not isinstance(data[key], str):
                findings.append(_finding(FindingCode.INVALID_METADATA, f"Metadata {key} must be a scalar string.", evidence.get(key)))
            else:
                values[key] = data[key]
        if "license" not in data or values.get("license") == "":
            findings.append(_finding(FindingCode.MISSING_LICENSE, "License metadata is absent or blank.", evidence.get("license")))
        elif "license" in values and not values["license"].strip():
            findings.append(_finding(FindingCode.MISSING_LICENSE, "License metadata is blank.", evidence.get("license")))
        return values, evidence, findings, end + 1
    except (yaml.YAMLError, RecursionError) as exc:
        return {}, {}, [_finding(FindingCode.INVALID_METADATA, f"Unreadable YAML metadata: {type(exc).__name__}.", _evidence(card, lines, 0, end + 1))], end + 1
    finally:
        if loader is not None:
            loader.dispose()


def _prose(lines: list[str], start: int) -> tuple[list[tuple[int, int]], list[tuple[int, int]], list[tuple[int, int]]]:
    """Return merged section ranges and non-code prose paragraphs."""
    headings: list[tuple[int, int, str]] = []
    paragraphs: list[tuple[int, int]] = []
    fence: tuple[str, int] | None = None
    paragraph_start: int | None = None
    for index in range(start, len(lines)):
        line = lines[index]
        marker = re.match(r"^ {0,3}(`{3,}|~{3,})(.*)$", line)
        was_fenced = fence is not None
        if marker:
            sequence, suffix = marker.groups()
            if fence is None:
                fence = sequence[0], len(sequence)
            elif sequence[0] == fence[0] and len(sequence) >= fence[1] and not suffix.strip():
                fence = None
        heading = HEADING.match(line) if not was_fenced and not marker else None
        if heading:
            title = re.sub(r"\s+#+\s*$", "", heading[2] or "")
            headings.append((index, len(heading[1]), " ".join(title.lower().split())))
        boundary = was_fenced or marker is not None or heading is not None or not line.strip()
        if boundary and paragraph_start is not None:
            paragraphs.append((paragraph_start, index))
            paragraph_start = None
        elif not boundary and paragraph_start is None:
            paragraph_start = index
    if paragraph_start is not None:
        paragraphs.append((paragraph_start, len(lines)))
    sections: list[tuple[int, int]] = []
    for position, (index, level, title) in enumerate(headings):
        if title not in SECTION_TITLES:
            continue
        end = next((i for i, other_level, _ in headings[position + 1:] if other_level <= level), len(lines))
        if sections and index < sections[-1][1]:
            sections[-1] = sections[-1][0], max(end, sections[-1][1])
        else:
            sections.append((index, end))
    return sections, paragraphs, [(index, index + 1) for index, _, _ in headings]


def _reference_url(card: FetchedCard, target: str) -> str | None:
    if target.startswith("#"):
        return None
    base = card.document_url.replace("/raw/", "/blob/", 1)
    try:
        resolved = urljoin(base, target)
        parsed = urlsplit(resolved)
    except ValueError:
        return None
    return resolved if parsed.scheme in {"http", "https"} and parsed.netloc else None


def _terms(card: FetchedCard, lines: list[str], values: dict[str, str], evidence: dict[str, EvidenceExcerpt],
           sections: list[tuple[int, int]], paragraphs: list[tuple[int, int]]) -> Iterator[tuple[str, EvidenceExcerpt]]:
    if values.get("license_link", "").strip():
        url = _reference_url(card, values["license_link"].strip())
        if url:
            yield url, evidence["license_link"]
    for start, end in paragraphs:
        if not any(left <= start < right for left, right in sections):
            continue
        excerpt = _evidence(card, lines, start, end)
        for match in LINK.finditer(excerpt.excerpt):
            url = _reference_url(card, match[2].strip("<>"))
            if url:
                yield url, excerpt


def referenced_terms(card: FetchedCard) -> list[tuple[str, EvidenceExcerpt]]:
    """HTTP(S) terms collected for sources; none of these documents is visited."""
    lines = card.text.splitlines(keepends=True)
    values, evidence, _, start = _metadata(card, lines)
    sections, paragraphs, headings = _prose(lines, start)
    return list(_terms(card, lines, values, evidence, sections, sorted(paragraphs + headings)))


def inspect_model_card(card: FetchedCard) -> ModelAssessment:
    lines = card.text.splitlines(keepends=True)
    values, evidence, findings, start = _metadata(card, lines)
    original = values.get("license")
    normalized: str | None = None
    if original and original.strip():
        normalized = ALIASES.get(original, original if is_supported_id(original) else None)
        if normalized is None:
            custom = original == "other" or original.startswith("LicenseRef-") or bool(values.get("license_name", "").strip())
            supporting = evidence.get("license")
            if custom and supporting is not None and "license_name" in evidence:
                name = evidence["license_name"]
                supporting = _evidence(card, lines, min(supporting.line_start, name.line_start) - 1,
                                       max(supporting.line_end, name.line_end))
            findings.append(_finding(FindingCode.CUSTOM_LICENSE if custom else FindingCode.UNKNOWN_LICENSE,
                                     f"Card license {original!r} is {'custom' if custom else 'unknown'}; Legal review is required.", supporting))
        elif normalized in {"CC-BY-NC-4.0", "CC-BY-NC-SA-4.0"}:
            findings.append(_finding(FindingCode.RESTRICTED_LICENSE, f"{normalized} is a known license with usage restrictions; Legal review is required.", evidence.get("license")))
    sections, paragraphs, headings = _prose(lines, start)
    prose: list[ModelFinding] = []
    for left, right in sections:
        prose.append(_finding(FindingCode.USAGE_CONTEXT, "Relevant usage context; a heading alone does not establish a binding restriction.", _evidence(card, lines, left, right)))
    detected = False
    for left, right in paragraphs:
        excerpt = _evidence(card, lines, left, right)
        if re.search(r"\b(?:license|licensing)\b", excerpt.excerpt, re.IGNORECASE) and not any(a <= left < b for a, b in sections):
            prose.append(_finding(FindingCode.USAGE_CONTEXT, "License-related prose for manual review.", excerpt))
        matches = list(dict.fromkeys(match[0].lower() for match in INDICATORS.finditer(" ".join(excerpt.excerpt.split()))))
        for indicator in matches:
            detected = True
            prose.append(_finding(FindingCode.POTENTIAL_RESTRICTION, f"Potential restriction indicator {indicator!r}; this is a review aid, not a legal interpretation.", excerpt))
    for url, excerpt in _terms(card, lines, values, evidence, sections, sorted(paragraphs + headings)):
        prose.append(_finding(FindingCode.REFERENCED_TERMS_UNREAD, f"Referenced terms at {url} were not fetched or assessed.", excerpt))
    prose.sort(key=lambda finding: finding.evidence.line_start)
    findings.extend(prose)
    if not detected:
        findings.append(_finding(FindingCode.NO_SUPPORTED_INDICATORS, "No supported restriction indicators detected; manual review is still required."))
    return ModelAssessment(status="inspected", document_url=card.document_url,
                           document_sha256=card.document_sha256, card_license=original,
                           normalized_license=normalized, license_evidence=evidence.get("license"),
                           findings=findings)
