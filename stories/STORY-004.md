# STORY-004: Local browser review UI

Status: Implemented; local verification passed

## User outcome

For a local presentation, select a CycloneDX JSON file from a repository directory,
run the existing machine review, inspect evidence, and record reviewer confirmations
or overrides without typing individual CLI commands. Keep the existing CLI and
classification behavior intact.

## Scope and architecture

Implement one small local browser application in `src/sbom_reviewer/ui/`, using
Python's standard-library HTTP server and buildless HTML/CSS/JavaScript. Add no
runtime or development dependencies. Reuse `load_sbom`, `load_policy`,
`review_components`, `save_review`, `load_review`, `record_decision`, and
`render_report`; keep policy, parsers, and saved-review semantics unchanged.

Launch:

```sh
uv run --locked sbom-reviewer ui --sbom-dir presentation --policy policy/licenses.json --review-dir presentation/output/ui
```

Serve only on `127.0.0.1`, default port 8765, with an optional `--port`. Print the
local URL; the user opens it in their browser. Ctrl-C stops the server cleanly.

## Acceptance criteria

1. The new `ui` command validates the input directory, policy, output directory,
   and port, reporting actionable CLI errors. Existing commands retain their
   behavior. Create the review directory if needed, without overwriting files.
2. The page lists immediate `.json` files in the configured SBOM directory. It
   accepts selections only from that directory; arbitrary paths, traversal, and
   symlinks escaping configured directories are refused. No uploads or editor.
3. A Run machine review button runs the existing review and saves a new uniquely
   named SQLite snapshot. Model-card fetching is an explicit, unchecked-by-default
   checkbox. A fresh review never inherits old human decisions. Failed input
   validation creates no review and shows an error without a success message.
4. Display original machine counts and separate human progress/counts. Component
   cards show name/version/type, declared licenses, recommendation, reason,
   sources, and expandable model-card evidence with findings and line excerpts.
   Missing, unavailable, and unread evidence remains explicit.
5. A reviewer name or ID field at the top supplies identity to each action. Each
   component has Confirm recommendation and Override controls. A dialog requires
   nonblank rationale for both; override offers the outcomes other than the
   original machine outcome: Allow, Needs review, Reject. Confirm means agreement
   with the original recommendation, including Reject or Needs review.
6. Committed actions update current human decisions and progress immediately.
   Original recommendations and evidence remain intact. Audit history remains
   visible with reviewer, rationale, action, outcome, event ID, and timestamp.
   Blank identity/rationale, invalid actions/components/outcomes, and storage
   errors do not report success or append events.
7. Saved reviews can be selected and reopened after a page/server restart from
   the configured review directory. Download HTML calls the existing renderer on
   the saved state, without fetching evidence or appending decisions.
8. Treat all SBOM, evidence, filenames, reviewer names, and rationale as untrusted
   data. Use escaped HTML or DOM text content, safe HTTP(S) source links, and no
   external assets. Bind to loopback only; validate Host, protect POST mutations
   with a per-server token and reject foreign origins, bound request sizes, and
   do not expose arbitrary filesystem paths or SQL through browser parameters.
9. Keep controls keyboard accessible, dialogs labeled, error/status feedback
   visible, and a readable responsive layout suitable for a presentation. Disable
   duplicate action submissions while pending and retain entered rationale after
   failures. Persist reviewer identity locally if useful; it is not authentication.
10. Add behavioral tests for HTTP review/decision/reopen/export workflows, machine
    snapshot preservation, independent reviews, opt-in fetching, validation errors,
    and file/request boundaries. Run the full pytest suite, strict dependency
    audit, and diff whitespace check. Smoke-test browser interactions when the
    available browser supports access to this local server; report any limit.

## Implementation plan

1. Write HTTP/CLI behavioral tests first and observe expected failures.
2. Implement a small typed application adapter plus local HTTP routing, wrapping
   existing functions. Use opaque/new review filenames and confined lookups.
3. Implement the static page and interaction script. Keep state in SQLite; browser
   state holds only the currently selected review and reviewer input.
4. Run focused tests, exercise the page, review the diff, and fix observed gaps.
5. Document launch and a short presentation flow. Run all required checks and
   record evidence before making the story implementation commit.

## Boundaries

This is a local single-reviewer demonstration. Caller-supplied reviewer names are
not authenticated. SQLite retains application-level append-only history. No
hosting, login, collaboration, bulk decisions, policy editor, uploads, runtime AI,
or changes to license interpretation. Live model-card retrieval can be slow or
unavailable; saved evidence is reused when reopening/exporting.

## Local validation handoff (2026-10-11)

Implemented on `story-004-local-ui`, from `main` at `2927eff`. The UI lives in a
separate package; the only existing Python module changed is the CLI dispatcher.
No dependencies were added and classification, model-card parsing, and saved-review
semantics remain unchanged.

- Baseline `uv run --locked pytest`: **419 passed**.
- New behavioral tests were run before implementation: **28 expected failures**
  for the missing UI, followed by red/green checks for asset serving, null/malformed
  JSON, non-ASCII mutation tokens, and symlink loops.
- `uv run --locked pytest tests/test_ui.py -q`: **34 passed**.
- Final `uv run --locked pytest`: **453 passed in 134.79s**.
- `sh scripts/audit-dependencies.sh`: passed; **No known vulnerabilities found**.
- `uv build --wheel --out-dir /tmp/sbom-reviewer-ui-wheel`: passed. Inspection of
  the wheel confirmed all four UI files match source bytes, with no cache files.
- `git diff --check`: passed.
- JavaScript syntax checked using the installed `gjs-console` engine. A temporary
  interaction harness executed the production script with controlled DOM/API
  boundary doubles: reviewer/rationale validation, override choices, request
  payload/token, failed-save rationale retention, history updates, original-machine
  confirmation, duplicate-submit guard, and literal text rendering passed.
- An independent temporary real CLI/HTTP smoke test passed: server launch,
  page/assets, the presentation inventory's offline **2 total / 1 Allow / 1 Needs
  review / 0 Reject** counts, confirm/override/restore events, unchanged machine
  evidence, failed-action history preservation, reopening, escaped downloaded
  HTML, interoperability with `show`, and clean Ctrl-C shutdown.

Browser visual QA could not run: the computer-use inventory exposed no browsers,
and both IAB and Chrome reported unavailable. JavaScript runtime checks with test
boundaries are not a visual browser test. Rehearse the actual layout and dialogs
in a browser before presenting. Jenkins has not been run for this story and the
branch has not been pushed. Live fetching was tested with a controlled card fixture;
no successful live model-card retrieval is claimed for this validation.
