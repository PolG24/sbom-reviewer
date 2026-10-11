# Saved reviews, reviewer decisions, and reports

Run commands from the repository root.

For a two-component rehearsal with optional live model-card fetching and successive
reports, follow [the presentation walkthrough](../presentation/COMMANDS.md).

Save a complete machine review to a **new** SQLite file, record individual human
actions, inspect the resulting JSON, and export a standalone HTML report:

```bash
uv run --locked sbom-reviewer review presentation/sboms/challenge.cyclonedx.json --policy presentation/policy/licenses.json --save-review review.sqlite
uv run --locked sbom-reviewer show review.sqlite
uv run --locked sbom-reviewer decide review.sqlite --component '#/components/0' --confirm --reviewer 'Example Reviewer' --reason 'Reviewed the supplied declaration and agree with the recommendation.'
uv run --locked sbom-reviewer decide review.sqlite --component '#/components/10' --override Allow --reviewer 'Example Reviewer' --reason 'Illustrative reviewer override for the demo; actual licensing remains to be verified.'
uv run --locked sbom-reviewer show review.sqlite
uv run --locked sbom-reviewer export review.sqlite --output review.html
```

The sample initially has **14 total / 4 Allow / 9 Needs review / 1 Reject** machine
recommendations and **0 recorded / 14 pending** human decisions. The two illustrative
actions above produce **2 recorded / 12 pending / 2 Allow / 0 Needs review / 0 Reject**
human counts. Machine recommendations and evidence stay unchanged. These example
decisions demonstrate the workflow, not verified licensing of the sample inventory.

**Confirm recommendation** records the original machine outcome, including Reject
or Needs review. It always refers to the saved snapshot, even after an override.
An override must differ from the machine outcome; use `--override 'Needs review'`
for outcomes containing spaces. Both actions require a nonblank reviewer and
rationale. Components without an event remain **Pending human review**, including
those with machine Allow. A recorded Needs review remains unresolved.

Each action appends a timestamped event with an increasing ID. `show` includes the
original `snapshot`, `saved_at`, current `reviewer_decisions` in component order,
the full `audit_log` in event order, and separate `reviewer_summary` counts.
Earlier events are retained; event IDs determine the latest action. Components
with identical names have separate histories keyed by their exact JSON pointers.
Use a new database for a fresh machine review; decisions do not carry over.

`review --save-review` still emits the existing review JSON, after the snapshot
commits. Without the flag, review opens no database. Saving also works with
`--fetch-model-cards`; only that explicit review flag permits evidence retrieval.
`decide` emits just the committed event JSON, `show` emits the saved view, and
`export` writes UTF-8 HTML with empty stdout. Successful commands exit 0 even with
Reject or Needs review. Invalid arguments, invalid/missing databases, unsupported
schema versions, and expected storage/output failures exit 2 with a stderr error.
Existing database and report paths are never overwritten.

Open `review.html` locally or attach it to a review handoff. The report needs no
server, scripts, external assets, or network fetches, and can be printed through
the browser. It includes original evidence and sources, current human decisions,
pending components, and superseded history. Supplied text is escaped; only valid
HTTP(S) references become clickable. Unavailable cards and unread linked terms
remain explicit. Repeated exports of the same saved state produce identical HTML.

This is a local demonstration workflow. Reviewer names are supplied by the caller,
without authentication. Append-only history is enforced by the application and
does not prevent someone editing SQLite directly. Collaboration, bulk decisions, signing, and direct PDF generation are outside
this version. A local browser workflow is described in the [browser guide](browser-ui.md).
Neither a recorded action nor the report establishes automatic legal approval,
verified licensing, or CRA compliance.
