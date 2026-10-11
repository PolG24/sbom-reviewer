# Local browser UI

Run commands from the repository root.

Run the presentation workflow in a browser, using the same review engine and
SQLite decision history as the CLI:

```bash
uv run --locked sbom-reviewer ui --sbom-dir presentation/sboms --policy presentation/policy/licenses.json --review-dir presentation/output/ui
```

Open the printed URL (normally `http://127.0.0.1:8765`). Use `--port 8766` if
that port is occupied. Stop the server with Ctrl-C. The review directory is
created if needed; generated reviews remain there between server runs.

1. Select an SBOM JSON file and click **Run machine review**. Model-card fetching
   is optional and off by default; enable it to collect live Hugging Face evidence.
2. Enter your reviewer name or ID at the top. Inspect machine recommendations,
   reasons, sources, and expandable model-card evidence.
3. Choose **Confirm recommendation** or **Override** for a component, enter a
   rationale, and save. Confirmation records the original machine outcome,
   including Reject or Needs review. Override requires a different outcome.
4. Check current human decisions, progress, and retained audit history. Select a
   saved review to resume it. Running machine review again creates a separate
   snapshot with no inherited human decisions.
5. Download the standalone HTML report for the current saved state. The report
   uses stored evidence and decisions; it does not fetch model cards again.

The file selector lists immediate `.json` files from the configured directory.
Review data stays in local SQLite files; machine results are preserved when human
choices are recorded. Existing CLI commands can inspect and export those files.
The server binds only to loopback and uses no external UI assets. Reviewer names
are supplied by the user, without authentication; this is a local demonstration,
not a shared service. See [STORY-004](../stories/STORY-004.md) for scope and validation.
