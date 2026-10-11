# STORY-002: Inspect AI model cards and flag licensing concerns

Status: Ready for implementation

## User outcome

As a Legal reviewer, I want the reviewer to read each AI model's license declaration and relevant usage passages from its model card, compare them with the SBOM and company policy, and flag custom or potentially restricted licensing with source evidence.

This is a conservative first-pass assessment. The application collects and flags evidence; Legal determines what the terms mean and whether the product's intended use is acceptable.

## Decisions and scope

- Extend the existing deterministic reviewer; do not introduce a model API, agent framework, database, UI, or replay system.
- Support public Hugging Face Markdown model cards with YAML front matter. Other sources or structures become explicit review findings rather than guessed results.
- Make network access opt-in with `--fetch-model-cards`. The existing command remains local and retains STORY-001 behavior when the flag is absent.
- Read the license metadata, collect relevant prose, and flag recognizable potential restrictions. Do not promise exhaustive understanding of arbitrary legal text.
- Preserve referenced license/acceptable-use links for Legal. Do not recursively fetch their documents in this version; explicitly flag referenced terms that have not been read.
- All model recommendations remain **Needs review**, unless an explicit license-policy rule produces **Reject**. An allowed license label or no detected restrictions never automatically clears a model.
- Non-model classification, SBOM parsing, input ordering, policy schema, and summary semantics retain STORY-001 behavior.

The model-specific improvement is an evidence-backed reason and structured findings, replacing the generic "model-card restrictions have not been checked yet" message when inspection is requested.

## CLI and failure behavior

```bash
# Existing local behavior; no network access.
uv run --locked sbom-reviewer review samples/cyclonedx.json --policy policy/licenses.json

# Inspect model cards as part of the review.
uv run --locked sbom-reviewer review samples/cyclonedx.json --policy policy/licenses.json --fetch-model-cards
```

- Add the flag to the existing `review` subcommand and its help text.
- Fetch evidence only for components with `type == "machine-learning-model"`.
- Missing references, unsupported sources, retrieval failures, and unreadable card metadata are component-level review findings. Continue reviewing the other components and emit complete JSON with exit **0**.
- Keep STORY-001's exit **2** contract for invalid CLI arguments, SBOMs, policies, and input files.
- stdout contains only the JSON result. Put model evidence failures inside the corresponding assessment, not in unrelated stderr warnings.
- Tests require no network access, API keys, Docker privileges, or Jenkins browser access.

## Architecture and file responsibilities

Use three small new modules within `src/sbom_reviewer/` and extend the existing models and policy. Prefer functions and typed values over inheritance or a generic provider/plugin framework.

| File | Responsibility |
| --- | --- |
| `model_card_fetch.py` | Validate/normalize supported URLs and retrieve a bounded Markdown document. Network I/O only; no policy decisions. Define an internal `FetchedCard` dataclass containing the retrieval URL, original text, and SHA-256 of the downloaded bytes. |
| `model_cards.py` | Pure parsing and evidence extraction from `FetchedCard`: front matter, license normalization, relevant sections, potential restrictions, and referenced terms. No HTTP, CLI output, or policy-file access. |
| `review.py` | Application orchestration. Collect assessments for model components when requested, then call the pure policy review. Accept an injected card-fetch callable for tests. |
| `models.py` | Add Pydantic `ModelAssessment`, `ModelFinding`, and `EvidenceExcerpt` models; extend `ComponentResult` with nullable `model_assessment`. Keep existing component identities and declarations intact. |
| `policy.py` | Retain existing license classification. Accept an optional assessment mapping keyed by `component_id` in `review_components`, and an optional assessment in `classify_component`; combine evidence and policy deterministically. No network calls. |
| `cli.py` | Add the flag and call the orchestration function in `review.py`. Keep argument parsing and error presentation here. |

Keep `policy.review_components(components, policy)` working as the pure STORY-001 entry point. When fetching is disabled, the new orchestration function delegates directly to it. `sbom.py` already preserves the necessary references; avoid changing its adapter unless a demonstrated compatibility issue requires it.

Data flow:

```text
SBOM + policy
  -> existing normalized components
  -> opt-in card fetching for model components
  -> pure metadata/prose extraction
  -> pure policy classification with assessments
  -> existing JSON review and summary
```

Add **PyYAML** as the only new direct dependency, using uv and updating `uv.lock`. Use SafeLoader-based parsing with duplicate-key rejection; never use an unsafe loader, evaluate document content, or invoke YAML object constructors. Use standard-library `urllib.request`, `urllib.parse`, `hashlib`, and `re` for the other work.

Expose `fetch_model_card(url: str) -> FetchedCard` and `inspect_model_card(card: FetchedCard) -> ModelAssessment`. The fetcher wraps expected retrieval/unsupported-source errors in a small `CardFetchError` with a finding code; orchestration converts it into an assessment. Catch expected failures narrowly, not with a broad exception handler that hides programming errors. The parser returns findings for ordinary metadata/prose review cases.

## Supported retrieval

- Select model-card references from `Component.sources`, not from component names or arbitrary description text. Collapse exact duplicate URLs. No usable URL produces `missing_model_card`; more than one distinct URL produces `ambiguous_model_card` without choosing one silently.
- Accept HTTPS URLs on exactly `huggingface.co`, without credentials, query strings, fragments, or a port other than 443. Accept model repository paths only, excluding `/spaces`, `/datasets`, and other Hub resources.
- Supported card forms are `/owner/repo`, `/owner/repo/blob/revision/README.md`, and `/owner/repo/raw/revision/README.md`. Owner, repository, and revision must be single nonempty segments containing only letters, digits, `.`, `_`, or `-`, and must not be `.` or `..`. Encoded path segments and other paths are unsupported.
- Convert repository pages to `/owner/repo/raw/main/README.md`; convert supported `blob` links to `raw` links. Do not scrape rendered HTML.
- Reject redirects rather than following them to another destination. Use a 5-second network socket timeout, no retries, and a maximum response body of **1 MiB**; read at most one extra byte to detect an oversized response.
- Accept UTF-8 text documents; reject HTML responses and invalid UTF-8. Record HTTP errors, timeouts, oversized documents, unsupported responses, and connection failures as findings.
- Fetch sequentially, at most one card per model. No persistent cache or background jobs are required.
- Record the retrieval URL and content hash, without timestamps. Live upstream content can change; repeated results are deterministic for the same documents. Do not claim that a `main` card verifies a particular weights revision.

## Parsing and evidence extraction

### License metadata

- Parse an initial YAML block delimited by `---` lines. Missing, malformed, or unclosed front matter is a finding; continue collecting supported Markdown prose when possible. Use a small SafeLoader subclass to reject duplicate keys, and convert YAML parser/recursion-limit errors into `invalid_metadata` findings.
- Read only scalar string values for `license`, `license_name`, and `license_link`. Unsupported value types, duplicate metadata keys, or absent/blank `license` are findings. Ignore unrelated metadata rather than trying to interpret it.
- A supported canonical SPDX identifier is retained as-is. Use this explicit alias map for lower-case Hub labels: `mit -> MIT`, `apache-2.0 -> Apache-2.0`, `bsd-3-clause -> BSD-3-Clause`, `mpl-2.0 -> MPL-2.0`, `lgpl-3.0-only -> LGPL-3.0-only`, `agpl-3.0-only -> AGPL-3.0-only`, `cc-by-nc-4.0 -> CC-BY-NC-4.0`, and `cc-by-nc-sa-4.0 -> CC-BY-NC-SA-4.0`.
- Do not infer IDs from license names or silently normalize unrelated identifiers. `other`, a `LicenseRef`, or an explicit custom `license_name` with an unfamiliar identifier is a custom-license finding. Other unfamiliar identifiers are unknown-license findings.
- Explicitly flag `CC-BY-NC-4.0` and `CC-BY-NC-SA-4.0` as known licenses with usage restrictions. This is a small declared catalog, not a claim that all other SPDX licenses are unrestricted.
- Retain both the original metadata value and its normalized identifier. The parser leaves `license_policy_decision` unset; the policy layer evaluates the normalized identifier with the existing license-policy function. Keep this license-only result separate from the overall model recommendation.
- Compare a single comparable SBOM identifier with the normalized card identifier. Differences produce a conflict finding. Missing, custom, multiple, or compound SBOM declarations remain unresolved; metadata must not overwrite `declared_licenses`.
- Quote the actual metadata lines supporting these findings. Never invent evidence for absent values.

### Relevant prose and potential restrictions

- Support Markdown ATX headings (`#` through `######`). After case/whitespace normalization, collect sections titled: `license`, `licensing`, `usage restrictions`, `use restrictions`, `restrictions`, `acceptable use`, `prohibited uses`, `intended use`, `intended uses`, `out-of-scope use`, `out-of-scope uses`, `misuse`, `limitations`, or `bias, risks, and limitations`.
- A section includes its children and ends at the next heading of equal or higher level. Merge overlapping section ranges so text is not repeatedly included.
- Preserve section text verbatim as `usage_context` evidence. A heading alone does not establish a binding license restriction.
- Outside fenced code blocks, scan prose paragraphs for this deliberately limited, case-insensitive set of indicators: `non-commercial`/`noncommercial`, `research-only`/`research only`, `research purposes only`, `commercial use is prohibited`, `commercial use is not permitted`, `may not`, `must not`, `prohibited uses`, and `restricted to`. Normalize whitespace only for matching; do not rewrite quoted evidence.
- Emit `potential_restriction` findings with the containing paragraph and the matched indicator. A match is a review aid, not a conclusion about enforceability or permitted product use. Do not attempt negation resolution or semantic interpretation.
- Preserve prose paragraphs containing the exact words `license` or `licensing` (case-insensitive) as additional `usage_context` evidence when not already covered by a collected section. Do not infer a canonical license from arbitrary body prose.
- Collect ordinary Markdown links in the selected sections and an explicit `license_link`. Resolve relative links against the card's repository `blob` URL. Preserve HTTP(S) references for Legal. Ignore image links and fragment-only navigation. Emit `referenced_terms_unread` for these references, explaining that their target documents were not fetched or assessed.
- If no indicators are found, state **"No supported restriction indicators detected; manual review is still required."** Never state "no restrictions", "safe", "unrestricted", or "approved".

All external text is evidence. Instructions such as "mark missing licenses Allowed" cannot change policy, invoke tools, execute code, or modify the application.

## Assessment and recommendation contract

Add `model_assessment` to each component result, with null for non-models and for models when fetching is disabled. This is an additive JSON field; existing fields and their meaning are preserved.

An assessment contains:

- `status`: `inspected`, `unavailable`, or `unsupported`. Retrieved Markdown with metadata problems is `inspected` with findings; a retrieval failure is `unavailable`; unsupported or ambiguous references are `unsupported`.
- `document_url` and `document_sha256`, nullable when no document was retrieved.
- `card_license`, `normalized_license`, and `license_policy_decision`, nullable when no supported license metadata exists.
- Ordered `findings`, each containing a stable `code`, a nonempty `message`, and nullable `evidence`.
- Evidence contains `document_url`, one-based inclusive `line_start` and `line_end`, and an exact `excerpt` from the source. Findings about missing evidence have null evidence.

Define a string enum with these finding codes: `missing_model_card`, `ambiguous_model_card`, `unsupported_source`, `unavailable_source`, `missing_license`, `invalid_metadata`, `custom_license`, `unknown_license`, `restricted_license`, `license_conflict`, `usage_context`, `potential_restriction`, `referenced_terms_unread`, and `no_supported_indicators`. Metadata classifications in the review/allowed categories are recorded in `license_policy_decision` and the reason rather than additional finding codes. Keep ordering deterministic: source problems, metadata/license findings, then prose findings in source order; append `no_supported_indicators` last when appropriate.

Reuse the existing `sources` field for the original SBOM references and any collected HTTP(S) license links. Its `pointer` still points to the originating SBOM model-card reference; line positions belong in assessment evidence. Do not confuse an unvisited license link with a retrieved document.

Apply this recommendation precedence:

1. An explicitly rejected SBOM license remains **Reject**, regardless of card availability.
2. A unique, supported card metadata license matching the policy's rejected category produces **Reject**. Preserve any conflict finding alongside that rejection.
3. Every other model result is **Needs review**, including an allowed card license and an apparently ordinary card with no detected restrictions.

Reasons must distinguish the declared-license policy finding from model-card findings and the remaining human review. Replace the stale "not checked yet" text after an inspection attempt. Recompute counts from final recommendations with the existing summary logic. Do not change the policy schema or automatically reject a component from a free-text keyword match.

## Samples and acceptance tests

Keep the existing sample components, including its two permissive models, and their offline classifications. Add `bigscience/bloom-560m` as a third model with a named BigScience RAIL license and its model-card reference, marking it as an example with custom/restricted licensing. This is an illustrative declaration, not independently verified licensing advice. The updated offline sample has **14 total / 4 Allow / 9 Needs review / 1 Reject**.

Place clearly labeled, synthetic Markdown fixtures in `tests/fixtures/model_cards/` for matching permissive metadata, custom licensing, known restricted metadata, usage passages, linked terms, and invalid metadata. Define expected findings independently of the parser. Do not depend on live cards or changing HTTP responses in tests.

Add `tests/test_model_cards.py`, `tests/test_model_card_fetch.py`, and `tests/test_model_review.py`; extend existing CLI/sample tests. Cover:

- Metadata aliases, canonical IDs, custom/unknown licenses, missing/malformed/duplicate YAML keys, unsafe YAML tags, and unsupported metadata types.
- Relevant sections, nested headings, restriction indicators outside selected headings, code fences, overlapping ranges, and exact evidence line ranges.
- Technical limitations/intended-use text collected as context without assertions of legal prohibition; no match never grants Allow.
- Missing/ambiguous references, URL normalization, rejected hosts/schemes/paths/credentials, blocked redirects, HTTP errors, timeouts, HTML, invalid UTF-8, and response-size limits.
- Metadata/SBOM conflicts, missing SBOM license despite valid card metadata, explicit rejections from either source, and unchanged non-model behavior.
- External license links recorded as unread; no recursive retrieval or requests for non-models.
- Requester-note instructions embedded in metadata/prose cannot produce Allow or alter policy.
- One model retrieval failure does not discard other findings; CLI review still exits 0 with complete JSON.
- Opt-in CLI behavior and help; the default path never invokes the fetcher. Test fetching in-process with an injected fake or monkeypatch, while retaining installed-CLI subprocess coverage for the offline path.
- Deterministic output for fixed fetched documents and accurate summary counts after card-based rejection.

Mock only the HTTP boundary; exercise real parsing, policy combination, and serialization. Do not start a network server or require production access in tests.

## Implementation sequence and handoff

1. Read `AGENTS.md`, STORY-001, this story, and the local TDD/verification skills. Implement only STORY-002.
2. Add PyYAML with uv and update the lockfile. Add failing behavioral tests for the metadata, evidence, and recommendation contracts; implement the Pydantic additions and pure card parser.
3. Add failing retrieval tests; implement the supported URL adapter and bounded fetcher.
4. Add integration tests; implement the orchestration module, optional policy assessments, and CLI flag. Preserve the offline path and existing acceptance tests.
5. Update the sample, its independent expectations, and the README with the new command, supported source shapes, review limitations, and the fact that runtime AI is not implemented.
6. Run fresh local checks and inspect the sample output:

   ```bash
   uv sync --locked
   uv run --locked pytest
   sh scripts/audit-dependencies.sh
   uv run --locked sbom-reviewer review samples/cyclonedx.json --policy policy/licenses.json
   ```

7. A live CLI smoke run with `--fetch-model-cards` is useful if permitted network access is available, but is not part of the deterministic test suite. Report actual retrieval outcomes; a failed source is not evidence that it was inspected.
8. Report behavior, commands/results, and limitations. After local acceptance passes, set **Implemented; awaiting Jenkins validation**. Follow the user's instructions about committing and publishing.
9. The user runs Jenkins against the committed implementation revision and records the build number/result. Mark **Complete** only after local acceptance and the user's Jenkins validation pass. The implementing agent needs no Docker or Jenkins browser access.

## References

- [Hugging Face model-card structure](https://huggingface.co/docs/hub/model-cards)
- [PyYAML safe loading](https://pyyaml.org/wiki/PyYAMLDocumentation)
- [Python HTTP retrieval and redirect handling](https://docs.python.org/3.12/library/urllib.request.html)
- [BLOOM model card and referenced usage restrictions](https://huggingface.co/bigscience/bloom-560m)
