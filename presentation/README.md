# Presentation pack

Run commands from the repository root.

| File | Purpose |
| --- | --- |
| [sboms/challenge.cyclonedx.json](sboms/challenge.cyclonedx.json) | Full challenge sample: 13 components, including three AI models, plus the metadata product. |
| [sboms/demo.cyclonedx.json](sboms/demo.cyclonedx.json) | Two-component inventory for the focused walkthrough. |
| [policy/licenses.json](policy/licenses.json) | Example company policy: Allowed, Review, and Rejected license lists. |
| [reports/challenge-review.html](reports/challenge-review.html) | Standalone report generated from the full sample, ready to open locally. |
| [COMMANDS.md](COMMANDS.md) | Review, model-card fetch, confirmation, override, audit history, and export walkthrough. |

The full sample's offline result is **14 total / 4 Allow / 9 Needs review / 1 Reject**.
The demo result is **2 total / 1 Allow / 1 Needs review / 0 Reject**. Both inventories
are illustrative; their declarations are not independently verified licensing
evidence. The full sample covers missing licenses, unknown/custom licenses,
compound expressions, rejected licenses, and AI models.

The delivered report is an **offline first-pass baseline**: no model cards were
fetched, no human actions were recorded, and all 14 components remain pending human
review. Its summary distinguishes machine recommendations from human decisions;
it does not establish approval for use or CRA compliance. The walkthrough shows
how reviewers record decisions while preserving the original recommendations.

## Browser demo

```bash
uv sync --locked
uv run --locked sbom-reviewer ui --sbom-dir presentation/sboms --policy presentation/policy/licenses.json --review-dir presentation/output/ui
```

Select `challenge.cyclonedx.json` to show the full deliverable or
`demo.cyclonedx.json` to follow the short walkthrough. The policy is outside the
SBOM directory, so it does not appear in the selector. Model-card fetching is
optional; leave it off for an offline rehearsal.

## Generate a fresh full-sample report

Use a new output directory each time; the CLI refuses to overwrite databases or
reports. This command creates one under the ignored rehearsal directory:

```bash
mkdir -p presentation/output
challenge_run=$(mktemp -d presentation/output/challenge-XXXXXX)
uv run --locked sbom-reviewer review presentation/sboms/challenge.cyclonedx.json --policy presentation/policy/licenses.json --save-review "$challenge_run/review.sqlite"
uv run --locked sbom-reviewer export "$challenge_run/review.sqlite" --output "$challenge_run/challenge-review.html"
```

Open the HTML file in the new directory. Fresh runs record a new saved timestamp;
repeat exports from the same saved state are byte-identical. The SQLite database
retains the machine snapshot for further inspection or reviewer decisions.
Rehearsal files under `output/` are
ignored; deliverable reports under `reports/` are intended for the repository.

`model-card.md` is a synthetic teaching fixture, not the actual license or card of
any real model. The live-fetch walkthrough does not use it. Historical stories
retain their original paths; use the current commands here when rehearsing.
