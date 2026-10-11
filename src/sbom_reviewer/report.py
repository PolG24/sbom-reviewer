"""Pure standalone HTML rendering; all supplied evidence remains escaped text."""

from html import escape
from urllib.parse import urlsplit

from sbom_reviewer.models import (
    ComponentResult, DecisionEvent, EvidenceExcerpt, ModelAssessment, SavedReview,
)


_STYLE = """
body { font-family: system-ui, sans-serif; color: #182430; background: #fff;
       max-width: 72rem; margin: 2rem auto; padding: 0 1.5rem; line-height: 1.5; }
h1, h2, h3, h4 { line-height: 1.25; }
article { border: 1px solid #aab6c2; border-radius: .4rem; padding: 1rem;
          margin: 1.5rem 0; }
dl { display: grid; grid-template-columns: minmax(9rem, 13rem) 1fr; gap: .3rem 1rem; }
dt { font-weight: 600; } dd { margin: 0; overflow-wrap: anywhere; white-space: pre-wrap; }
pre { white-space: pre-wrap; overflow-wrap: anywhere; padding: .8rem;
      background: #f1f4f7; border-left: 3px solid #657c91; }
a { color: #144c87; overflow-wrap: anywhere; }
table { border-collapse: collapse; margin: 1rem 0; width: 100%; }
th, td { border: 1px solid #aab6c2; text-align: left; padding: .5rem; }
.pending { font-weight: 600; color: #654500; }
li { margin-bottom: .5rem; overflow-wrap: anywhere; }
@media print { body { margin: 0; max-width: none; } h2, h3, h4 { break-after: avoid; }
              pre, tr { break-inside: avoid; } }
"""


def _text(value: str | int | None) -> str:
    return escape(str(value) if value is not None else "Not supplied", quote=True)


def _field(label: str, value: str | int | None) -> str:
    return f"<dt>{_text(label)}</dt><dd>{_text(value)}</dd>"


def _http_url(value: str) -> bool:
    if any(character.isspace() or ord(character) < 32 or ord(character) == 127 for character in value):
        return False
    if "\\" in value:
        return False
    try:
        url = urlsplit(value)
        return (url.scheme in {"http", "https"} and bool(url.hostname)
                and url.username is None and url.password is None
                and (url.port is None or 1 <= url.port <= 65535))
    except ValueError:
        return False


def _reference(value: str | None) -> str:
    if value is None:
        return "No URL supplied"
    if _http_url(value):
        return f'<a href="{_text(value)}">{_text(value)}</a>'
    return _text(value)


def _evidence(evidence: EvidenceExcerpt) -> str:
    return (f"<p>Evidence document: {_reference(evidence.document_url)}<br>"
            f"Lines {_text(evidence.line_start)}–{_text(evidence.line_end)}</p>"
            f"<pre>{_text(evidence.excerpt)}</pre>")


def _assessment(assessment: ModelAssessment | None) -> str:
    if assessment is None:
        return "<h4>Model-card assessment</h4><p>No model-card assessment saved.</p>"
    parts = ["<h4>Model-card assessment</h4><dl>", _field("Status", assessment.status),
             f"<dt>Document URL</dt><dd>{_reference(assessment.document_url)}</dd>",
             _field("Document SHA-256", assessment.document_sha256),
             _field("Original card license", assessment.card_license),
             _field("Normalized license", assessment.normalized_license),
             _field("License-only policy decision", assessment.license_policy_decision), "</dl>"]
    if assessment.license_evidence is not None:
        parts.extend(["<h4>License metadata evidence</h4>", _evidence(assessment.license_evidence)])
    parts.append("<h4>Model-card findings</h4><ul>")
    for finding in assessment.findings:
        parts.append(f"<li><strong>{_text(finding.code)}</strong>: {_text(finding.message)}")
        if finding.evidence is not None:
            parts.append(_evidence(finding.evidence))
        parts.append("</li>")
    parts.append("</ul>")
    return "".join(parts)


def _event(event: DecisionEvent) -> str:
    action = "Confirm recommendation" if event.action == "confirm" else "Override"
    return ("<dl>" + _field("Event ID", event.event_id) + _field("Component ID", event.component_id)
            + _field("Human decision", event.decision) + _field("Action", action)
            + _field("Reviewer", event.reviewer) + _field("Rationale", event.reason)
            + _field("Recorded at (UTC)", event.recorded_at.isoformat()) + "</dl>")


def _component(component: ComponentResult, event: DecisionEvent | None) -> str:
    parts = [f'<article data-component-id="{_text(component.component_id)}">',
             f"<h3>{_text(component.name)}</h3><dl>",
             _field("Component ID", component.component_id), _field("BOM reference", component.bom_ref),
             _field("Version", component.version), _field("Type", component.type), "</dl>",
             "<h4>Original declared licenses</h4>"]
    if component.declared_licenses:
        parts.append("<ul>" + "".join(f"<li>{_text(value)}</li>" for value in component.declared_licenses) + "</ul>")
    else:
        parts.append("<p>None declared; license evidence is missing.</p>")
    parts.extend(["<h4>Machine recommendation</h4><dl>", _field("Recommendation", component.decision),
                  _field("Machine reason", component.reason), "</dl><h4>Current human decision</h4>"])
    parts.append(_event(event) if event is not None else '<p class="pending">Pending human review</p>')
    parts.append("<h4>Original source references</h4><ul>")
    for source in component.sources:
        parts.append(f"<li>{_text(source.kind)}: {_reference(source.url)}"
                     f"<br>Original pointer: {_text(source.pointer)}</li>")
    parts.extend(["</ul>", _assessment(component.model_assessment), "</article>"])
    return "".join(parts)


def _counts(title: str, counts: list[tuple[str, int]]) -> str:
    return (f"<h2>{_text(title)}</h2><table><thead><tr>"
            + "".join(f'<th scope="col">{_text(label)}</th>' for label, _ in counts)
            + "</tr></thead><tbody><tr>"
            + "".join(f"<td>{_text(value)}</td>" for _, value in counts) + "</tr></tbody></table>")


def render_report(saved: SavedReview) -> str:
    """Render deterministically from stored data, with no I/O or export timestamp."""
    machine, human = saved.snapshot.summary, saved.reviewer_summary
    parts = ['<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">',
             '<meta name="viewport" content="width=device-width, initial-scale=1">',
             "<title>SBOM reviewer report</title><style>", _STYLE, "</style></head><body>",
             "<h1>SBOM reviewer report</h1><dl>",
             _field("Saved at (UTC)", saved.saved_at.isoformat()),
             _field("Policy version", saved.snapshot.policy_version), "</dl>",
             "<p>Machine recommendations are preliminary policy assessments. Recorded human decisions "
             "retain the reviewer's rationale; confirmation agrees with the original recommendation, "
             "including Reject or Needs review. Needs review remains unresolved. "
             "This report does not establish verified licensing, automatic legal approval, or CRA compliance. "
             "Source links and quoted evidence are supplied references; unread terms remain unassessed.</p>",
             _counts("Original machine counts", [("Total", machine.total), ("Allow", machine.allow),
                     ("Needs review", machine.needs_review), ("Reject", machine.reject)]),
             _counts("Human-decision counts", [("Total", human.total), ("Recorded", human.recorded),
                     ("Pending", human.pending), ("Allow", human.allow),
                     ("Needs review", human.needs_review), ("Reject", human.reject)]),
             "<h2>Components</h2>"]
    current = {event.component_id: event for event in saved.reviewer_decisions}
    parts.extend(_component(component, current.get(component.component_id)) for component in saved.snapshot.results)
    parts.append("<h2>Complete decision history</h2>")
    if saved.audit_log:
        parts.append("<ol>" + "".join(f"<li>{_event(event)}</li>" for event in saved.audit_log) + "</ol>")
    else:
        parts.append("<p>No reviewer actions recorded.</p>")
    parts.append("</body></html>\n")
    return "".join(parts)
