# Opt-in model-card inspection

Run commands from the repository root.

```bash
uv run --locked sbom-reviewer review presentation/sboms/challenge.cyclonedx.json --policy presentation/policy/licenses.json --fetch-model-cards
```

Only `machine-learning-model` components are fetched, sequentially, using their SBOM
model-card references. Duplicate URLs collapse; ambiguous references require review.
Supported sources are public HTTPS URLs on exactly `huggingface.co`: `/owner/repo`,
`/owner/repo/blob/revision/README.md`, or `/owner/repo/raw/revision/README.md`.
Repository pages use `raw/main/README.md`; blob links use raw Markdown. Owner, repository,
and revision must be single segments of letters, digits, `.`, `_`, or `-`, excluding
`.` and `..`. Encoded segments, other Hub resources, credentials, queries, fragments,
and ports other than 443 are unsupported. Redirects are blocked. Each request has a
5-second socket timeout, no retries, and a 1 MiB response limit. Cards must be UTF-8
text; HTML is rejected.

Each result adds nullable `model_assessment` (null on the default path and for
non-models). Inspected cards record their retrieval URL, downloaded-byte SHA-256,
original and normalized metadata license, a separate `license_policy_decision`, and
ordered findings with verbatim excerpts and inclusive source line ranges.
`license_evidence` retains the metadata lines for policy conflict provenance.
Safe YAML parsing rejects duplicate keys, unsafe tags, and YAML aliases before
expansion. Alias-based metadata produces `invalid_metadata`; supported prose is
still collected. Missing, malformed, custom,
unknown, or restricted metadata remains explicit evidence for Legal.
Missing/unsupported references and retrieval failures produce component findings;
review still emits complete JSON and exits 0, with no unrelated stderr warnings.

The deterministic parser collects selected license/usage sections and scans prose
outside fenced code for a limited set of potential restriction indicators. Technical
limitations and intended-use passages are context, not legal prohibitions. Keyword
matches never automatically reject a model; an explicitly rejected SBOM or supported
card metadata license can produce Reject. An allowed license label, missing SBOM
evidence, or no supported indicators still requires manual review. Instructions in
external text cannot change policy or execute tools. Runtime AI is not implemented;
there is no model API or semantic interpretation of arbitrary legal text.

HTTP(S) license and acceptable-use links in selected sections and `license_link`
metadata are preserved in `sources`, pointing to the originating SBOM model-card
reference. They receive `referenced_terms_unread` findings: their documents are not
recursively fetched or assessed. Live cards may change; repeated results are
deterministic for the same downloaded documents. A `main` card does not verify a
particular weights revision. These are conservative evidence flags; Legal determines
the meaning of the terms and whether the intended product use is acceptable.

These are preliminary policy recommendations, not human approvals or a statement
of CRA compliance. This version does not evaluate Boolean
license expressions, license compatibility, vulnerabilities, or SPDX documents.
