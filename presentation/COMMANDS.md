# Two-component presentation walkthrough

Run these blocks **from the repository root**, in order. Read the notes between
steps; they explain what to point out to the panel. The illustrative inventory has
a fictional MIT library and the real `sentence-transformers/all-MiniLM-L6-v2`
embedding model, declared Apache-2.0. There is no metadata product,
so the review has exactly two components.

Step 2 fetches the model card directly from Hugging Face through the CLI and
requires network access. Later steps use that saved evidence without fetching
again. Live card contents and availability can change; inspect the assessment
before presenting its findings. The local synthetic `model-card.md` is not used
in this walkthrough.

```bash
uv sync --locked
mkdir -p presentation/output
```

Use a fresh output directory or new filenames when repeating the walkthrough.
Saving reviews and exporting reports refuse to overwrite existing files.

## Browser alternative

For the same review and decision flow with buttons instead of individual commands:

```bash
uv run --locked sbom-reviewer ui --sbom-dir presentation --policy policy/licenses.json --review-dir presentation/output/ui
```

Open the printed local URL. Select `cyclonedx.json`, optionally enable model-card
fetching, and run machine review. Enter `Panel Reviewer` at the top. Inspect the
library and model evidence, then confirm or override each recommendation with an
explicit rationale. The page shows the original machine result alongside the
human decision and retains each event in the history. Download the HTML report
for the current state, or select a saved review to resume later.

Keep the model-card fetch checkbox off for an offline rehearsal. With the
presentation inventory, expect **2 total / 1 Allow / 1 Needs review / 0 Reject**
and initially **0 recorded / 2 pending**. Confirming the model records Needs review;
it does not approve the model for use. Live fetching may produce different evidence
or counts, as described in step 2 below. Each new machine review is a new snapshot.
Stop the server with Ctrl-C. The CLI walkthrough below remains available.

## 1. Start with declarations only

```bash
uv run --locked sbom-reviewer review presentation/cyclonedx.json --policy policy/licenses.json
```

Look at the two results:

- `#/components/0`: library, **Allow**, because MIT matches the example policy.
- `#/components/1`: model, **Needs review**, despite the Apache-2.0 declaration.
- `model_assessment` is null. No model card was fetched and no database was opened.
- Machine counts: **2 total / 1 Allow / 1 Needs review / 0 Reject**.

These are supplied declarations, not independently verified component licenses.
The IDs are original JSON pointers, not component names. The model's omitted
version stays null; the library's version is preserved.

Now save exactly that result and export it:

```bash
uv run --locked sbom-reviewer review presentation/cyclonedx.json --policy policy/licenses.json --save-review presentation/output/baseline.sqlite
uv run --locked sbom-reviewer export presentation/output/baseline.sqlite --output presentation/output/00-baseline.html
```

Open `00-baseline.html`: both components say **Pending human review**, including
the library with machine Allow. There is no saved model-card assessment.

## 2. Fetch the Hugging Face model card and save an enriched review

The SBOM's model-card reference points to the real MiniLM repository. Run the
existing CLI with its opt-in fetch flag:

```bash
uv run --locked sbom-reviewer review presentation/cyclonedx.json --policy policy/licenses.json --fetch-model-cards --save-review presentation/output/review.sqlite
```

Inspect `model_assessment` in the printed model result:

- `status: inspected` means the card was read. The assessment records the raw
  README URL and a SHA-256 of the downloaded bytes. A hash identifies those bytes;
  it does not verify licensing or authenticity.
- If the card still declares `apache-2.0`, the parser preserves that value,
  normalizes it to `Apache-2.0`, and the policy sets `license_policy_decision` to Allow.
- `license_evidence` quotes the actual metadata lines. Findings quote their
  original line ranges; use those ranges rather than assuming fixed line numbers.
- `usage_context` collects supported intended-use and limitation sections.
  Technical limits do not establish legal prohibitions.
- `potential_restriction` and `referenced_terms_unread` appear only when the
  fetched card contains supported indicators or relevant terms links. Linked
  documents are not fetched. MiniLM need not contain either finding.
- With the currently allowed metadata license, the overall model decision remains
  **Needs review**. A license-only Allow does not clear a model, and no supported
  restriction indicators still requires manual review.

The CLI normalizes the reference to raw README Markdown and fetches sequentially
with a 5-second socket timeout and 1 MiB limit. It rejects redirects and unsupported
sources. Only model components are fetched; linked terms are not recursively visited.

Fetch failures still produce a complete review with exit 0. `status: unavailable`
means the card was not read: inspect the finding and retry with a new database
filename after resolving connectivity. Do not describe that result as inspected.
Upstream license changes can also change the recommendation and counts; check the
actual result before following the expected outcomes below.

`review.sqlite` is a **new snapshot**. We did not enrich or alter `baseline.sqlite`.
Fresh machine evidence gets a new database and no inherited human decisions.

```bash
uv run --locked sbom-reviewer show presentation/output/review.sqlite
uv run --locked sbom-reviewer export presentation/output/review.sqlite --output presentation/output/01-evidence.html
```

Open `01-evidence.html`. The card assessment is visible, but there are still
**0 recorded / 2 pending** human decisions. HTML exports are static snapshots;
an already-open report does not update when the database changes.

## 3. Confirm the library recommendation

```bash
uv run --locked sbom-reviewer decide presentation/output/review.sqlite --component '#/components/0' --confirm --reviewer 'Panel Reviewer' --reason 'Checked the supplied MIT declaration and agree with the policy recommendation.'
uv run --locked sbom-reviewer show presentation/output/review.sqlite
uv run --locked sbom-reviewer export presentation/output/review.sqlite --output presentation/output/02-library-confirmed.html
```

Expect event **1**, human Allow for the library, and **1 recorded / 1 pending**.
Open the new report and compare it with `01-evidence.html`.

## 4. Confirm that the model still needs review

```bash
uv run --locked sbom-reviewer decide presentation/output/review.sqlite --component '#/components/1' --confirm --reviewer 'Panel Reviewer' --reason 'The model-card evidence still requires human licensing review; an allowed metadata label does not establish approval for use.'
uv run --locked sbom-reviewer show presentation/output/review.sqlite
uv run --locked sbom-reviewer export presentation/output/review.sqlite --output presentation/output/03-model-confirmed.html
```

Expect event **2**, human **Needs review** for the model, and **0 pending**.
Every component now has a recorded action, but the model is still unresolved.
**Confirm recommendation does not mean approve for use.**

## 5. Override the model, then restore the original recommendation

First record an explicit, illustrative override:

```bash
uv run --locked sbom-reviewer decide presentation/output/review.sqlite --component '#/components/1' --override Allow --reviewer 'Second Reviewer' --reason 'Illustrative presentation exception only; no real licensing approval is established.'
uv run --locked sbom-reviewer show presentation/output/review.sqlite
uv run --locked sbom-reviewer export presentation/output/review.sqlite --output presentation/output/04-model-overridden.html
```

Expect event **3**. The model's current human outcome becomes Allow, but its
machine Needs review and all fetched model-card evidence remain visible.
Events 1 and 2 remain in the audit history.

Now confirm again:

```bash
uv run --locked sbom-reviewer decide presentation/output/review.sqlite --component '#/components/1' --confirm --reviewer 'Panel Reviewer' --reason 'Restore agreement with the original machine recommendation; investigation remains open.'
uv run --locked sbom-reviewer show presentation/output/review.sqlite
uv run --locked sbom-reviewer export presentation/output/review.sqlite --output presentation/output/05-model-restored.html
```

Expect event **4**, current human Needs review, and all four events in order.
Confirmation refers to the original machine snapshot, not the preceding override.
Run the SQLite inspection block again to see the unchanged snapshot and four rows.

| Report | Recorded | Pending | Human Allow | Human Needs review | Audit events |
| --- | ---: | ---: | ---: | ---: | ---: |
| 01-evidence | 0 | 2 | 0 | 0 | 0 |
| 02-library-confirmed | 1 | 1 | 1 | 0 | 1 |
| 03-model-confirmed | 2 | 0 | 1 | 1 | 2 |
| 04-model-overridden | 2 | 0 | 2 | 0 | 3 |
| 05-model-restored | 2 | 0 | 1 | 1 | 4 |

For a fetched card with allowed metadata, machine counts stay
**2 total / 1 Allow / 1 Needs review / 0 Reject** throughout the saved-review actions.
Human Reject counts stay zero in this walkthrough.

## 6. Try one invalid action and a repeatable export

This redundant override must fail with exit 2 and direct you to confirmation.
It must not create event 5:

```bash
uv run --locked sbom-reviewer decide presentation/output/review.sqlite --component '#/components/0' --override Allow --reviewer 'Panel Reviewer' --reason 'Already matches the machine recommendation.'
uv run --locked sbom-reviewer show presentation/output/review.sqlite
```

Export the same state to a different path and compare the files:

```bash
uv run --locked sbom-reviewer export presentation/output/review.sqlite --output presentation/output/06-repeat.html
cmp presentation/output/05-model-restored.html presentation/output/06-repeat.html
```

`cmp` should be silent and exit 0. Export uses stored timestamps and does not fetch
anything or append events. Reusing an existing report path must fail without
overwriting it.

## Implementation points to explain

- SBOM adapter → optional card fetch → pure evidence parser → pure policy → JSON
  machine review. Saving is optional and happens after that review is built.
- `model_cards/parser.py` extracts metadata and excerpts; `policy.py` combines that
  evidence with declarations. No runtime AI or interpretation of arbitrary legal text.
- `saved_reviews/storage.py` preserves the machine snapshot and appends events; `saved_reviews/decisions.py`
  validates actions and derives current human decisions and counts.
- `saved_reviews/report.py` renders saved data into escaped, standalone HTML. It performs no
  fetching and does not execute Markdown/HTML from the evidence.
- Reviewer names are caller-supplied, without authentication. Append-only behavior
  is an application guarantee, not protection against direct SQLite edits.
