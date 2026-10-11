# SBOM Reviewer

First pass review of Software Bills of Materials (SBOMs) for legal acceleration.

## Development

Install Python 3.12 and [uv](https://docs.astral.sh/uv/), then install the locked dependencies:

```bash
uv sync --locked
```

Review a CycloneDX JSON **1.6** inventory against a local policy:

```bash
uv run --locked sbom-reviewer review samples/cyclonedx.json --policy policy/licenses.json
uv run --locked sbom-reviewer review samples/cyclonedx.json --policy policy/licenses.json > review.json
```

Help is available at both levels:

```bash
uv run --locked sbom-reviewer --help
uv run --locked sbom-reviewer review --help
```

Run the behavioral tests and strict dependency audit:

```bash
uv run --locked pytest
sh scripts/audit-dependencies.sh
```

The audit exports every locked runtime and development dependency with hashes,
excluding only the local editable application package. `pip-audit --strict`
fails on known vulnerabilities, lookup failures, and dependencies it cannot audit.

## Review behavior and limitations

The JSON result contains `policy_version`, ordered `results`, and summary counts.
Findings contain the original component JSON pointer, supplied `bom-ref`, name,
nullable version, type, all declared licenses, recommendation, reason, and source
references. The traversal visits `metadata.component` first, then the top-level
components and their children in depth-first input order. It ignores services and
dependency edges; it does not discover missing dependencies. Empty inventories
return zero findings. Repeated inputs produce identical output.

Recommendations are **Allow**, **Needs review**, or **Reject**. Completed reviews
exit **0**, even with rejected components. Missing arguments, unreadable files,
invalid JSON/policy/schema, and unsupported formats/versions exit **2**, with an
error on stderr and no review JSON. The dependency audit retains its separate
strict failure contract.

SBOM and policy JSON reject the nonstandard numeric tokens `NaN`, `Infinity`,
and `-Infinity` before schema validation. These words inside quoted strings remain
ordinary input data.
Both inputs allow at most **128 nested JSON object/array levels**, counting the root
container as level 1. Deeper inputs exit 2 with a nesting-limit message before
schema validation or deserialization; they never return a truncated review.

`policy/licenses.json` is an example company policy, not universal legal judgments.
All categories and a nonempty version are required; duplicate/overlapping entries,
extra fields, and wrong types are rejected. Categories may be empty. Matching is
case-sensitive and exact, for a single SPDX ID or an expression containing exactly
that ID. Missing evidence, custom licenses (use `license.name`), identifiers absent
from policy, multiple licenses, and compound expressions require review. No license
is inferred from descriptions, names, or URLs. Instructions within SBOM data cannot
change policy. Explicitly rejected model licenses remain Reject; all other models
require review until model-card restrictions are checked in STORY-002.

Validation uses the library's bundled schemas and requires its `json-validation`
extra. Review is local and deterministic: it needs no API keys or network access,
and never fetches or executes referenced content. Source URLs are HTTP(S) references
only; absent evidence has an explicit null URL and a declaration pointer. When an
SPDX ID has no supplied license URL, the result adds its canonical SPDX definition.
That definition does not independently verify the component's licensing.

The sample is an **illustrative product inventory**, not a claim about this
reviewer's dependencies. It has 12 components plus a metadata product, with expected
counts **13 total / 4 Allow / 8 Needs review / 1 Reject**. It includes the declared
Apache-2.0 `sentence-transformers/all-MiniLM-L6-v2` and MIT `BAAI/bge-small-en-v1.5`
models, license links, and model-card references. Model-card inspection is pending;
the sample's declarations and links are illustrative, unverified input evidence.

These are preliminary policy recommendations, not human approvals or a statement
of CRA compliance. Human decisions, audit persistence, an attachable Legal report,
and dedicated export are later stories. This version does not evaluate Boolean
license expressions, license compatibility, vulnerabilities, or SPDX documents.

## Agent workflow

Read [AGENTS.md](AGENTS.md) and the relevant story before implementation. Work on
one story at a time, add behavioral tests for its acceptance criteria, and report
the commands run and any remaining limitations.

## Local Jenkins

The repository includes a local Jenkins controller and Python 3.12 agent. Follow
the setup instructions in [docs/local-jenkins.md](docs/local-jenkins.md).
Jenkins is bound to `127.0.0.1:8080` and is intended for local use only.
