The STORY-001 review matrix uses `classification_policy.json`, deliberately
different from the sample company policy. AGPL is allowed, MIT requires review,
and Apache/BSD are rejected here to detect hard-coded sample decisions. These
are test choices, not legal advice.

Extend `classification_cases.json` with an object containing:

- `id`: a unique descriptive pytest case name.
- `component`: a schema-valid CycloneDX 1.6 component, with name and type.
- `decision`: the independently expected final recommendation.
- `declared_licenses`: the original declaration strings in input order.
- `reason_parts`: meaningful findings that the explanation must contain.

The runner validates the inventory once, then calls `classify_component` for
each case. It checks identity, declarations, provenance, repeatability, unchanged
inputs, offline classification, and aggregate decisions. No production helper
computes expected decisions. Model-card inspection remains deferred in this
story. Multiple declarations require selection review even when all entries
are rejected; a single rejected model declaration remains Reject.

`test_review_input_edges.py` retains the regressions for non-JSON numeric
constants and excessive input nesting. They remain active tests without skips or
xfails. `test_json_nesting.py` also checks the documented 128-level boundary,
decoder recursion errors, quoted strings, and complete supported inventories.
