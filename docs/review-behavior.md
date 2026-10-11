# Review behavior and limitations

Run commands from the repository root.

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

`presentation/policy/licenses.json` is an example company policy, not universal legal judgments.
All categories and a nonempty version are required; duplicate/overlapping entries,
extra fields, and wrong types are rejected. Categories may be empty. Matching is
case-sensitive and exact, for a single SPDX ID or an expression containing exactly
that ID. Missing evidence, custom licenses (use `license.name`), identifiers absent
from policy, multiple licenses, and compound expressions require review. No license
is inferred from descriptions, names, or URLs. Instructions within SBOM data cannot
change policy. Explicitly rejected model licenses remain Reject; every other model
requires manual review, including after model-card inspection.

Validation uses the library's bundled schemas and requires its `json-validation`
extra. The default review is local and deterministic: it needs no API keys or network
access. Opt-in model-card inspection is described in the [model-card guide](model-cards.md). Source URLs are HTTP(S) references
only; absent evidence has an explicit null URL and a declaration pointer. When an
SPDX ID has no supplied license URL, the result adds its canonical SPDX definition.
That definition does not independently verify the component's licensing.

The sample is an **illustrative product inventory**, not a claim about this
reviewer's dependencies. It has 13 components plus a metadata product, with expected
offline counts **14 total / 4 Allow / 9 Needs review / 1 Reject**. It includes the declared
Apache-2.0 `sentence-transformers/all-MiniLM-L6-v2` and MIT `BAAI/bge-small-en-v1.5`
models and `bigscience/bloom-560m` with a named BigScience RAIL license as an example
of custom/restricted licensing. The sample's declarations and links are illustrative,
unverified input evidence, not independently verified licensing advice.
