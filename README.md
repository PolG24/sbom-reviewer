# SBOM Reviewer

First-pass open-source license review for Legal. Each SBOM component receives
**Allow**, **Needs review**, or **Reject**, with a reason and source references.
Reviewers make the final call; every confirmation or override is logged. A
standalone HTML report provides summary counts, evidence, and decision history.

## Design

Python validates CycloneDX 1.6 JSON, then applies a versioned license policy.
Optional Hugging Face model-card inspection extracts license metadata, usage
context, and potential restrictions. Missing or uncertain evidence produces
**Needs review**; instructions embedded in input cannot change policy.

The CLI and local browser UI share the same review engine. SQLite keeps the
original machine snapshot separate from reviewer events, preserving recommendations
after overrides. HTML exports escape untrusted text. See the
[decision flow](docs/decision-flow.md) and [reviewer workflow](docs/reviewer-workflow.md).

## Run the demo

Requires Python 3.12 and `uv`. From the repository root:

```bash
uv sync --locked
uv run --locked sbom-reviewer ui --sbom-dir presentation/sboms \
  --policy presentation/policy/licenses.json --review-dir presentation/output/ui
```

Open the printed URL. Select `challenge.cyclonedx.json` for the full sample
(13 components, including three AI models, plus the metadata product), or
`demo.cyclonedx.json` for the [short walkthrough](presentation/COMMANDS.md).
Leave model-card fetching off for an offline demo.

## How the AI's work was checked

AI-assisted implementation followed [stories](stories/) and [AGENTS.md](AGENTS.md),
one story at a time, with commit history retained. Behavioral tests cover license
classification, missing and hostile evidence, model-card failures, reviewer
decisions, snapshot preservation, and report escaping. The instruction to allow
missing licenses is ignored.

Run `uv run --locked pytest` and `sh scripts/audit-dependencies.sh`.
The [Jenkins pipeline](Jenkinsfile) runs both and fails if either fails; the audit
checks locked application and development dependencies. See
[verification details](docs/development.md) and [Jenkins setup](docs/local-jenkins.md).

## Deliverables

[Sample SBOM](presentation/sboms/challenge.cyclonedx.json) ·
[License policy](presentation/policy/licenses.json) ·
[Offline report](presentation/reports/challenge-review.html) ·
[Model-card report](presentation/reports/challenge-review-model-cards.html) ·
[Presentation pack](presentation/README.md)

The offline report is an illustrative baseline: **4 Allow / 9 Needs review /
1 Reject**, with all 14 human decisions pending and no model cards fetched.

## Known limitations

- CycloneDX 1.6 only; no SPDX input, component vulnerability lookup, compound
  license evaluation, or license compatibility analysis.
- Model-card extraction is deterministic, without a runtime LLM. Linked terms
  remain unread; supplied declarations are not independently verified.
- Reviewer identity is unauthenticated; audit history is append-only through the
  application but not protected against direct database edits.
- The CLI uses `argparse`; Click decorators could simplify command definitions.

See [detailed behavior and limitations](docs/review-behavior.md). Recommendations
and reports do not establish legal approval or CRA compliance.
