# STORY-003: Record reviewer decisions, retain an audit log, and export a report

Status: Implemented; awaiting Jenkins validation

## Local validation handoff

Implemented on `story-003`, created from `main` at `db96190`. The implementation
adds typed reviewer actions, one immutable machine snapshot per SQLite database,
transactional append-only events, save/decide/show commands, and standalone HTML
export. No dependencies were added, and STORY-001/002 classification and parsing
behavior remain unchanged. Changes are committed in stages for decisions/storage,
CLI workflows, a storage cleanup fix, and report/documentation integration.

Local acceptance on 2026-10-11:

- `uv sync --locked`: passed.
- `uv run --locked pytest`: **419 passed**. Real SQLite and installed-CLI tests
  cover machine-evidence preservation, confirmation/override semantics, independent
  component/review histories, same-timestamp ordering, transaction commit failures,
  invalid input/database paths, HTML escaping, and deterministic offline exports.
- `sh scripts/audit-dependencies.sh`: passed; **No known vulnerabilities found**.
- `git diff --check`: passed.
- Offline sample `review --save-review`, `decide --confirm`, `decide --override Allow`,
  `show`, and two `export` commands: all exited 0 with their specified stdout/stderr.
  Initial machine counts stayed **14 total / 4 Allow / 9 Needs review / 1 Reject**;
  initial human counts were **0 recorded / 14 pending**. The two illustrative
  decisions produced **2 recorded / 12 pending / 2 Allow / 0 Needs review / 0 Reject**.
  The original snapshot stayed unchanged and audit event IDs 1 and 2 were retained.
  HTML contained all 14 components and 12 pending states; repeated exports were
  byte-identical and left the database bytes unchanged.

The workflow uses caller-supplied reviewer names, without authentication. History
is append-only at the application level, not cryptographically protected against
direct database edits. Browser collaboration, signing, and direct PDF generation
remain outside scope. No live evidence fetch is needed for this story's acceptance.

Jenkins validation remains pending. Validate the final committed `story-003`
revision, with Tests and Dependency audit passing, and record the tested revision,
build number, and result before marking this story Complete. No Jenkins build has
been run or claimed here. The branch has not been pushed.

## User outcome

As a Legal reviewer, I want to confirm or override component recommendations,
retain a history of my decisions, and export a readable report with the original
machine evidence and my rationale.

This is a local workflow suitable for an interview demonstration. Keep the
implementation focused on ordinary review tasks and relevant failure cases.

## Agreed architecture and scope

- Extend the existing CLI. Use standard-library SQLite for persistence and
  self-contained HTML for the exported report. Add no dependencies.
- Store the complete machine review as an immutable snapshot. Keep all original
  recommendations, reasons, declarations, sources, model assessments, and counts.
- Store human decisions separately as append-only events. Derive each component's
  current human decision from its latest event.
- Use one SQLite file per saved review. The database path identifies the review;
  `component_id` identifies a component within that snapshot. A fresh machine
  review uses a new database file and does not inherit earlier human decisions.
- Reviewer names are supplied through the CLI. Authentication, a browser UI,
  collaboration, bulk decisions, document signing, and direct PDF generation
  are outside this story. Application-level append-only history is not a
  cryptographic guarantee against someone editing the database directly.
- Leave STORY-001/002 classification and model-card parsing behavior intact.
  General refactoring of those modules is deferred.

Data flow:

```text
Existing review -> saved machine snapshot
                        + reviewer decision events
                        -> current human decisions and complete audit history
                        -> JSON inspection or HTML report
```

## CLI workflow

```bash
# Existing review behavior; no persistence unless explicitly requested.
uv run --locked sbom-reviewer review samples/cyclonedx.json --policy policy/licenses.json

# Save the complete review and still emit the existing review JSON on stdout.
uv run --locked sbom-reviewer review samples/cyclonedx.json --policy policy/licenses.json --save-review review.sqlite

# Agree with the original machine recommendation for this component.
uv run --locked sbom-reviewer decide review.sqlite --component '#/components/0' --confirm --reviewer 'Example Reviewer' --reason 'Reviewed the supplied declaration and agree with the recommendation.'

# Record a different human outcome. This example is an illustrative demo decision.
uv run --locked sbom-reviewer decide review.sqlite --component '#/components/10' --override Allow --reviewer 'Example Reviewer' --reason 'Illustrative reviewer override for the demo; actual licensing remains to be verified.'

# Inspect the snapshot, current human decisions, counts, and audit history.
uv run --locked sbom-reviewer show review.sqlite

# Export a report that can be opened locally or attached to a review handoff.
uv run --locked sbom-reviewer export review.sqlite --output review.html
```

- Add optional `--save-review PATH` to `review`; it works with or without
  `--fetch-model-cards`. Without it, do not open or create a database. With it,
  persist the snapshot successfully before printing the original review JSON.
- `decide` requires the database path, exact component ID, nonblank reviewer name,
  nonblank reason, and exactly one of `--confirm` or `--override`. Override choices
  are the existing strings `Allow`, `Needs review`, and `Reject`; quote values
  containing spaces in the shell.
- A successful `decide` prints only the newly persisted event as JSON.
  `show` prints only the saved-review view as JSON. `export` writes UTF-8 HTML
  to the requested path and leaves stdout empty.
- All successful commands exit **0**, including decisions or reports containing
  Reject or Needs review. Invalid arguments, unknown component IDs, invalid
  reviewer input, missing/invalid databases, and expected storage/output failures
  exit **2** with an actionable stderr error and no success JSON or traceback.
- Refuse to overwrite an existing database when saving a new review, or an
  existing report when exporting. Do not implicitly create databases from
  `decide`, `show`, or `export`.
- Keep the existing command help and add help for the new commands and options.
  Only an explicit model-card fetch during `review` may use the network.

## Reviewer decision semantics

Use the term **confirm recommendation**, rather than treating every confirmation
as approval for use.

| Action | Recorded human outcome |
| --- | --- |
| Confirm | The original machine recommendation, including Reject or Needs review |
| Override | The explicitly selected outcome, different from the machine recommendation |
| No action | Null human decision; Pending human review |

- Confirmation always refers to the machine snapshot, even after an earlier
  override. It can therefore restore agreement with the original recommendation.
- Reject an override equal to the machine recommendation with a message directing
  the reviewer to use confirmation.
- Both actions require a rationale. Explicit overrides may record Allow for a
  machine Reject or Needs review, including missing-license cases. The original
  machine result and uncertainty remain visible; no machine policy is weakened.
- A recorded Needs review still indicates an unresolved outcome. Recording an
  action does not imply that the component has been approved for use.
- A later action appends another event. Preserve the earlier reviewer, outcome,
  reason, and timestamp. Repeated intentional actions remain separate events.
- Do not match components by name or version. Identically named components have
  independent histories based on their original JSON pointers.

## Data and persistence contract

Keep `ReviewResult` and its existing JSON contract unchanged. Add typed models for
decision events and the saved-review view in `models.py` as needed.

The saved-review view contains:

- `snapshot`: the original `ReviewResult` with its original component ordering.
- `saved_at`: a timezone-aware UTC timestamp recorded when saving the review.
- `reviewer_decisions`: latest events for components with a human decision,
  ordered by the components' snapshot order.
- `audit_log`: every decision event, ordered by increasing event ID.
- `reviewer_summary`: `total`, `recorded`, `pending`, `allow`, `needs_review`, and
  `reject`. Outcome counts cover only current human decisions. They sum to
  `recorded`; `recorded + pending == total`. The machine summary stays unchanged.

Each decision event contains a database-assigned increasing integer `event_id`,
`component_id`, `action` (`confirm` or `override`), `decision`, `reviewer`, `reason`,
and timezone-aware UTC `recorded_at`. Whitespace-only names/reasons are invalid.
Use event IDs to determine the latest event; timestamps may coincide.

Use a small schema with one snapshot record and a decision-events table. Each
event is both the human-decision record and its audit entry; avoid a second mutable
copy of current decisions. Record a schema version and reject unsupported versions
clearly. No migration framework or multiple-review catalog is required.

Use parameterized SQL and transactions. Validate the component and append its
event within one transaction; report success only after commit. A failed action
must leave the previous history unchanged. The application must never update or
delete snapshot contents or historical events. Close connections reliably.

Provide explicit typed functions for saving a snapshot, loading a saved review,
and recording a decision. Expected SQLite and file errors should reach the CLI
through a small storage error type; programming errors must remain visible.

## HTML report contract

Render a standalone HTML document with inline CSS. It must open without a server,
JavaScript, external styles, fonts, or downloaded assets. Browser printing may be
used manually; generating a PDF is outside this story.

Include:

- A title, saved-review timestamp, policy version, original machine counts, and
  separate human-decision counts and pending count.
- Every component in snapshot order, with its identity, name, nullable version,
  type, and original declared licenses.
- Explicitly labeled machine recommendation and reason, plus the current human
  decision, action, reviewer, rationale, and timestamp when present. Components
  without an event must say **Pending human review**, even when the machine says Allow.
- Original source URLs and pointers. Include model-card assessment status,
  document URL/hash, license evidence, findings, and quoted excerpts with line
  ranges when available. Unavailable cards and unread referenced terms must
  remain distinguishable from inspected evidence.
- The complete decision history, including superseded decisions, in event order.

Treat snapshot fields, evidence, reviewer names, and rationales as untrusted text.
Escape all dynamic HTML text and attribute values. Make only valid HTTP(S)
references clickable; display other supplied values as escaped text. Do not render
embedded Markdown/HTML from model cards or fetch any links during export.

Reports are deterministic for the same saved snapshot and event history. Use stored
timestamps rather than adding a fresh export timestamp. The report must distinguish
machine recommendations and recorded human decisions without claiming verified
licensing, automatic legal approval, or CRA compliance.

## File responsibilities

| File | Responsibility |
| --- | --- |
| `decisions.py` | Pure validation and preparation of reviewer actions; derive current decisions and human counts from ordered events. |
| `storage.py` | SQLite schema, immutable snapshot persistence, transactional event append, loading, and expected storage errors. |
| `report.py` | Pure HTML rendering from the saved-review view, including escaped evidence and history. |
| `models.py` | Typed event and saved-review models; preserve existing machine-result models. |
| `cli.py` | Parse commands, coordinate existing review and new persistence/decision/report functions, write output, and present expected errors. |

Prefer small functions, named typed values, and explicit data flow. A small storage
object is acceptable if it clarifies connection ownership; no repository framework,
class hierarchy, generic event bus, or replay system is needed.

## Acceptance tests

Use real SQLite databases in pytest temporary directories and synthetic reviews.
Retain installed-CLI subprocess coverage. Tests require no network, API keys,
Docker, or Jenkins access. Focus on these realistic behaviors:

- Saving and loading preserves the complete machine result, including model
  evidence and sources. Existing review output is unchanged and the default
  command creates no database.
- Confirming each recommendation records the same outcome. An override records
  a different outcome with its reviewer and rationale, while the machine fields
  and summary remain unchanged. Confirming after an override uses the original
  machine recommendation.
- An override from machine Reject or missing evidence to human Allow is explicit
  and auditable. Pending components never acquire implicit human approval.
- Two decisions on the same component retain both events and expose the latest
  as current. Same-timestamp events use their event IDs. Same-named components
  and separate saved reviews do not share decisions.
- Missing or conflicting action flags, blank reviewer/reason, invalid outcomes,
  redundant overrides, and unknown component IDs are rejected. A failed action
  leaves the existing snapshot and audit log intact.
- Missing, invalid, and unsupported-version databases fail clearly. Existing
  snapshot/report paths are not overwritten. Expected write failures do not
  print success JSON.
- `show` returns accurate current-human counts and ordered history; every CLI
  command follows its exit, stdout, stderr, and help contracts.
- HTML contains every component, pending states, original evidence, current
  decisions, and superseded history. Malicious HTML in names, reasons, evidence,
  and URLs cannot become executable markup or unsafe clickable links.
- Export does not mutate the database or fetch evidence. Repeated export of the
  same saved state produces identical HTML at distinct output paths.

For the existing offline sample, initial machine counts remain **14 total / 4 Allow /
9 Needs review / 1 Reject**. Initial human counts are **0 recorded / 14 pending**.
After the two illustrative CLI actions above, human counts are **2 recorded /
12 pending / 2 Allow / 0 Needs review / 0 Reject**; machine counts remain unchanged.

## Implementation sequence and handoff

1. Read `AGENTS.md`, STORY-001/002, this story, and the local TDD/verification
   skills. Implement only STORY-003; keep the interview scope in mind.
2. Add failing behavioral tests for confirm/override semantics, history, and
   human counts; implement the new typed models and pure decision functions.
3. Add persistence tests; implement SQLite snapshot storage and transactional
   event recording. Keep persistence separate from the existing reviewer.
4. Add CLI tests; implement `--save-review`, `decide`, and `show` with expected
   failure handling and unchanged default review behavior.
5. Add report/export tests; implement the escaped HTML renderer and `export`.
6. Document the short demonstration workflow and limitations in README. Preserve
   meaningful commits for decisions/storage, CLI, and report integration.
7. Run fresh local checks:

   ```bash
   uv sync --locked
   uv run --locked pytest
   sh scripts/audit-dependencies.sh
   git diff --check
   ```

8. Run the offline save/confirm/override/show/export workflow in a temporary
   directory. Inspect JSON counts, unchanged machine recommendations, retained
   history, and the generated HTML. Report actual results and remaining limits.
9. After local acceptance passes, set **Implemented; awaiting Jenkins validation**.
   Follow the user's instructions about committing and publishing. Mark Complete
   only after the user validates the committed implementation in Jenkins and
   records the tested revision, build number, and result.
