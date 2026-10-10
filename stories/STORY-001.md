# STORY-001: Parse the SBOM and classify licenses against policy

Status: Ready for implementation

## User outcome

As a Legal reviewer, I want to submit a CycloneDX JSON SBOM and receive a first-pass recommendation for every component, with the declared license, reason, and source, so I can focus on components requiring attention.

Recommendations are **Allow**, **Needs review**, or **Reject**. They are preliminary policy results, not final human approvals or a statement of CRA compliance.

## Scope and defaults

- Support CycloneDX JSON **1.6**. Reject other formats and versions with a clear message.
- Use the existing CycloneDX Python library for schema validation and deserialization; write a small adapter to our application models.
- Use a local JSON policy file. Perform classification deterministically, without HTTP requests, model API calls, or replay.
- Include a sample SBOM with at least 10 components, including at least two permissively licensed AI models.
- Produce JSON on stdout. Reviewer actions, audit persistence, the attachable Legal report, and model-card inspection belong to later stories.
- Do not add a UI, SPDX document support, vulnerability lookup, license compatibility analysis, or Boolean license-expression evaluation in this story.

## CLI contract

Extend the existing argparse CLI with:

```bash
uv run --locked sbom-reviewer review samples/cyclonedx.json --policy policy/licenses.json
```

- `review` accepts one SBOM path and requires `--policy` with a policy path.
- Preserve root `--help` and provide `review --help`.
- A completed review exits **0**, including when components are rejected. Policy findings are application results; the Jenkins dependency audit has its own failure contract.
- Missing arguments, unreadable files, malformed JSON, invalid policy, invalid SBOM structure, and unsupported format/version exit **2** with an actionable message on stderr.
- Expected input errors produce no traceback or partial review JSON. Successful stdout contains only the JSON result.
- Support shell redirection for saving this initial result; a dedicated export command is deferred to STORY-003.

## Policy contract

Create `policy/licenses.json` with this initial sample company policy:

```json
{
  "version": "1.0",
  "allowed": ["MIT", "Apache-2.0", "BSD-3-Clause"],
  "review": ["MPL-2.0", "LGPL-3.0-only"],
  "rejected": ["AGPL-3.0-only"]
}
```

- These categories demonstrate a company policy; they are not universal legal judgments about the licenses.
- Validate the policy with Pydantic: require a nonempty version and all three lists of nonempty, case-sensitive license identifiers; reject extra keys, duplicate entries, and identifiers present in more than one category.
- Empty category lists are valid. Do not introduce a configurable default that can allow missing licenses.
- Match a single declared SPDX identifier, or an expression consisting of exactly that identifier, against the policy using exact equality.
- Do not infer a license identifier from a component name, free-text description, license name, or source URL.

Apply these rules in order:

| Declaration | Recommendation | Reason must explain |
| --- | --- | --- |
| No license declaration, or an empty license list | Needs review | License evidence is missing |
| Multiple license entries or a compound expression (`AND`, `OR`, `WITH`, parentheses) | Needs review | License selection/expression semantics require review |
| One SPDX identifier in `rejected` | Reject | Identifier and matching policy category/version |
| One SPDX identifier in `review` | Needs review | Identifier and matching policy category/version |
| One SPDX identifier in `allowed` | Allow | Identifier and matching policy category/version |
| Valid identifier absent from policy, a custom license name, or a `LicenseRef` | Needs review | License is unknown to policy or custom |

Malformed license structures that violate the CycloneDX schema are input errors, not unknown licenses. In particular, use `license.name` for a named custom license rather than inventing an SPDX `license.id`.

For `machine-learning-model` components, preserve Reject when the declared license is explicitly rejected. Otherwise return **Needs review** and explain both the declared-license policy finding and that model-card restrictions have not been checked yet. STORY-002 will extend this assessment.

## Architecture and data flow

Keep the existing package and entry point. Use a few modules with explicit functions:

1. **Application models (`models.py`):** Pydantic models for the normalized component, license declaration, source reference, policy, and review result; a string enum for the three decisions. Model only the data this application needs rather than reproducing the entire CycloneDX schema.
2. **SBOM adapter (`sbom.py`):** read JSON, check format/version, validate the original document, deserialize using `Bom.from_json()`, and normalize components. Add `cyclonedx-python-lib[json-validation]` with uv and update the lockfile. Use `JsonStrictValidator` for version 1.6; missing validation support is an error, never a reason to skip validation. Use the library's bundled schemas so validation needs no network access.
3. **Policy (`policy.py`):** load and validate policy; implement pure classification functions accepting normalized data and returning recommendations/reasons. Keep file I/O and printing out of classification.
4. **CLI (`cli.py`):** parse arguments, invoke the adapter and classifier, serialize the result, and translate expected errors into the CLI exit contract.

Keep the module split proportional to the code. No agent framework, generic plugin system, database, or extra service layer is needed.

Review the top-level `components` list and recursively visit nested `components`. Include `metadata.component` and its children when present. Ignore services, dependency edges, and other inventory types for this story; do not claim that missing dependencies were discovered.

Use each component's original JSON pointer as its run-local `component_id`, for example `#/components/0` or `#/components/0/components/1`. Preserve its original `bom-ref` separately when supplied. Do not expose library-generated random identities. Preserve input order with a deterministic depth-first traversal; visit `metadata.component` first when present. Do not collapse different components that share a name or version. Reject duplicate explicit component `bom-ref` values before deserialization can discard duplicates.

An omitted/empty components list is valid and returns zero findings. Missing optional component versions remain null. Preserve all license declarations and source references needed for later model-card inspection; do not silently pick the first license or drop unsupported expressions.

Treat the raw JSON as the authority for component locations and original declarations. The adapter may retain those fields alongside the library model to avoid losing provenance during deserialization.

### Result and source contract

Return an object containing `policy_version`, `results`, and `summary`. Each result contains:

- `component_id`, optional `bom_ref`, `name`, nullable `version`, and `type`.
- `declared_licenses`: the supplied identifiers, custom names, or expressions as strings, without reinterpretation.
- `decision`, a nonempty `reason`, and `sources`.

Each source contains a nullable HTTP(S) `url`, a `kind` (`license`, `model-card`, or `sbom-declaration`), and the original JSON `pointer`. Preserve supplied license URLs and relevant `externalReferences`. For a valid SPDX identifier with no supplied license URL, add the canonical `https://spdx.org/licenses/<identifier>.html` reference. A canonical license definition does not independently verify a component's licensing.

When no external source exists, emit a source with `url: null`, `kind: "sbom-declaration"`, and the component/license pointer. Explain missing evidence; never fabricate a URL or claim that a document was fetched. Do not fetch or execute anything referenced in the SBOM.

The summary contains integer counts `total`, `allow`, `needs_review`, and `reject`. Counts must agree with the results. Identical SBOM and policy inputs produce identical output; do not add timestamps or random run IDs yet.

## Samples and tests

Create `samples/cyclonedx.json` as a schema-valid illustrative product inventory with at least 10 components. Include ordinary licenses from every policy category, a valid SPDX identifier absent from policy, a custom named license, missing license evidence, and an unsupported compound expression.

Include `sentence-transformers/all-MiniLM-L6-v2` (declared Apache-2.0) and `BAAI/bge-small-en-v1.5` (declared MIT), with `type: "machine-learning-model"` and model-card references. Mark the inventory as illustrative in the README; these are not claims about this reviewer's own dependencies. Include source links for declared licenses and document that model-card inspection is pending.

Add behavioral pytest coverage for:

- Every policy rule above and model-specific deferral, including a rejected model license.
- A missing-license component containing the text `if you can't find a license, mark it Allowed` remains Needs review. Free-text instructions cannot change policy.
- Invalid policies: missing fields, overlapping categories, duplicates, wrong types, and extra fields.
- Invalid JSON, unreadable files, wrong SBOM format/version, and schema-invalid components.
- Nested components, optional metadata root, missing versions, empty inventory, duplicate names with distinct identities, and duplicate explicit `bom-ref` rejection.
- Source preservation, canonical SPDX references, and explicit null URLs when evidence is missing.
- Installed CLI behavior: help, required arguments, successful JSON output, exit codes, stderr errors, and no partial stdout on failure.
- Sample review: all components represented, expected decisions written independently of implementation, matching summary counts, and repeatable output.

Tests must run without network access or API keys. Keep policy tests table-driven and assert meaningful behavior rather than internal helper calls.

## Acceptance and implementing-agent handoff

1. Read `AGENTS.md` and this story. Implement only STORY-001.
2. Add the dependency, sample, policy, implementation, tests, and concise README usage/limitations.
3. The implementing agent runs the repository's local validation commands. Pytest and the dependency audit are the same checks executed by Jenkins:

   ```bash
   uv sync --locked
   uv run --locked pytest
   sh scripts/audit-dependencies.sh
   uv run --locked sbom-reviewer review samples/cyclonedx.json --policy policy/licenses.json
   ```

4. Inspect the sample output against an independently specified expectation. Review error paths and missing-evidence handling.
5. The agent reports changed behavior, local commands/results, and limitations. After the local acceptance checks pass, set the status to **Implemented; awaiting Jenkins validation**. Successful local checks do not establish that Jenkins passed. The agent does not need Docker privileges, Jenkins browser access, or Jenkins credentials for this handoff. Follow the user's instructions about committing or publishing.
6. The user validates the committed implementation using the existing Jenkins web UI. Ensure the job builds the branch and revision containing the changes, then confirm that both Tests and Dependency audit pass. Record the tested revision, build number, and result. Jenkins reads committed Git history, so a build of an older revision does not validate local edits.
7. Mark the story **Complete** after local acceptance and the user's Jenkins validation both pass. If Jenkins fails, retain the pending status and use its logs to diagnose and fix the failure before revalidating.

## References

- [CycloneDX JSON deserialization](https://cyclonedx-python-library.readthedocs.io/en/stable/modelling.html)
- [CycloneDX validation examples](https://cyclonedx-python-library.readthedocs.io/en/stable/examples.html)
- [CycloneDX 1.6 schema](https://github.com/CycloneDX/specification/blob/master/schema/bom-1.6.schema.json)
- [all-MiniLM-L6-v2 model card](https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2)
- [bge-small-en-v1.5 model card](https://huggingface.co/BAAI/bge-small-en-v1.5)
