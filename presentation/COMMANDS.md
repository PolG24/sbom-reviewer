# Two-component presentation walkthrough

Run these blocks **from the repository root**, in order. Read the notes between
steps; they explain what to point out to the panel. Both components are fictional:
an MIT library and an Apache-2.0 embedding model. There is no metadata product,
so the review has exactly two components.

The main walkthrough is offline and repeatable. `model-card.md` deliberately
contains an allowed license label, a research-only passage, a terms link, and a
technical limitation. It is synthetic evidence, not real licensing advice. The
optional last step uses a real model and the actual network-fetching CLI.

```bash
uv sync --locked
mkdir -p presentation/output
```

Use a fresh output directory or new filenames when repeating the walkthrough.
Saving reviews and exporting reports refuse to overwrite existing files.

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

## 2. See how the assessment is built, then save an enriched review

Display the fixture with line numbers:

```bash
nl -ba presentation/model-card.md
```

There is no CLI option for reading local model cards. This small Python block uses
the existing injected-fetch function: it substitutes the local fixture for HTTP
retrieval, while running the real SBOM adapter, card parser, policy combination,
and snapshot storage. The fixture URL is an evidence label; it was not downloaded.

```bash
uv run --locked python - <<'PY'
from hashlib import sha256
from pathlib import Path

from sbom_reviewer.model_card_fetch import FetchedCard, normalize_model_card_url
from sbom_reviewer.model_cards import inspect_model_card
from sbom_reviewer.policy import load_policy
from sbom_reviewer.review import review_components
from sbom_reviewer.sbom import load_sbom
from sbom_reviewer.storage import save_review

body = Path("presentation/model-card.md").read_bytes()
card = FetchedCard(
    normalize_model_card_url("https://huggingface.co/panel-demo/mini-embedder"),
    body.decode("utf-8"),
    sha256(body).hexdigest(),
)
assessment = inspect_model_card(card)
Path("presentation/output/parser-assessment.json").write_text(
    assessment.model_dump_json(indent=2) + "\n", encoding="utf-8",
)
snapshot = review_components(
    load_sbom(Path("presentation/cyclonedx.json")),
    load_policy(Path("policy/licenses.json")),
    fetch_model_cards=True,
    card_fetch=lambda requested_url: card,
)
save_review(Path("presentation/output/review.sqlite"), snapshot)
print(snapshot.model_dump_json(indent=2))
PY
```

Open `parser-assessment.json`, then compare it with the printed model result:

- The parser records `inspected`, the document URL, and a SHA-256 of the fixture
  bytes. A hash identifies those bytes; it does not verify licensing or authenticity.
- It preserves `apache-2.0` and normalizes the supported alias to `Apache-2.0`.
  The parser-only `license_policy_decision` is null; the policy layer sets it to Allow.
- `license_evidence` quotes line 2. Findings quote their original line ranges.
- `potential_restriction` flags “research purposes only” on line 13.
- `referenced_terms_unread` preserves the linked terms without fetching them.
- `usage_context` includes the technical limitation without declaring it a legal prohibition.
- The overall model decision remains **Needs review**. A license-only Allow does
  not clear a model, and a prose indicator does not automatically reject it.

`review.sqlite` is a **new snapshot**. We did not enrich or alter `baseline.sqlite`.
Fresh machine evidence gets a new database and no inherited human decisions.

```bash
uv run --locked sbom-reviewer show presentation/output/review.sqlite
uv run --locked sbom-reviewer export presentation/output/review.sqlite --output presentation/output/01-evidence.html
```

Open `01-evidence.html`. The card assessment is visible, but there are still
**0 recorded / 2 pending** human decisions. HTML exports are static snapshots;
an already-open report does not update when the database changes.

## 3. Inspect SQLite before and after each action

Run this block now and again after each decision below. It opens SQLite read-only.
The snapshot timestamp and hash should stay the same; event rows accumulate.

```bash
uv run --locked python - <<'PY'
from contextlib import closing
from hashlib import sha256
from pathlib import Path
import sqlite3

path = Path("presentation/output/review.sqlite")
with closing(sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)) as db:
    print("Schema version:", db.execute("PRAGMA user_version").fetchone()[0])
    saved_at, snapshot_json = db.execute("SELECT saved_at, review_json FROM snapshot").fetchone()
    print("Snapshot saved at:", saved_at)
    print("Snapshot hash:", sha256(snapshot_json.encode("utf-8")).hexdigest())
    print("Decision events:")
    for row in db.execute(
        "SELECT event_id, component_id, action, decision, reviewer, reason, recorded_at "
        "FROM decision_events ORDER BY event_id"
    ):
        print(row)
PY
```

There is one `snapshot` record and an append-only `decision_events` table.
There is no separate mutable table of current decisions. `show` derives each
component's latest event using its increasing event ID, then computes human counts.
Each decision validates the component and inserts its event in one transaction;
the CLI prints success only after commit. No action updates the machine snapshot.

## 4. Confirm the library recommendation

```bash
uv run --locked sbom-reviewer decide presentation/output/review.sqlite --component '#/components/0' --confirm --reviewer 'Panel Reviewer' --reason 'Checked the supplied MIT declaration and agree with the policy recommendation.'
uv run --locked sbom-reviewer show presentation/output/review.sqlite
uv run --locked sbom-reviewer export presentation/output/review.sqlite --output presentation/output/02-library-confirmed.html
```

Expect event **1**, human Allow for the library, and **1 recorded / 1 pending**.
Open the new report and compare it with `01-evidence.html`.

## 5. Confirm that the model still needs review

```bash
uv run --locked sbom-reviewer decide presentation/output/review.sqlite --component '#/components/1' --confirm --reviewer 'Panel Reviewer' --reason 'The synthetic research-only passage and unread terms still need investigation.'
uv run --locked sbom-reviewer show presentation/output/review.sqlite
uv run --locked sbom-reviewer export presentation/output/review.sqlite --output presentation/output/03-model-confirmed.html
```

Expect event **2**, human **Needs review** for the model, and **0 pending**.
Every component now has a recorded action, but the model is still unresolved.
**Confirm recommendation does not mean approve for use.**

## 6. Override the model, then restore the original recommendation

First record an explicit, illustrative override:

```bash
uv run --locked sbom-reviewer decide presentation/output/review.sqlite --component '#/components/1' --override Allow --reviewer 'Second Reviewer' --reason 'Illustrative presentation exception only; no real licensing approval is established.'
uv run --locked sbom-reviewer show presentation/output/review.sqlite
uv run --locked sbom-reviewer export presentation/output/review.sqlite --output presentation/output/04-model-overridden.html
```

Expect event **3**. The model's current human outcome becomes Allow, but its
machine Needs review, restriction excerpt, and unread terms remain visible.
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

Machine counts always stay **2 total / 1 Allow / 1 Needs review / 0 Reject**.
Human Reject counts stay zero in this walkthrough.

## 7. Try one invalid action and a repeatable export

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

## 8. Optional: run the real model-card fetcher

Keep the offline demonstration above as your reliable rehearsal. For a live run,
make a separate two-component input using the real MiniLM model from the repository's
existing illustrative sample:

```bash
uv run --locked python - <<'PY'
import json
from pathlib import Path

document = json.loads(Path("presentation/cyclonedx.json").read_text(encoding="utf-8"))
samples = json.loads(Path("samples/cyclonedx.json").read_text(encoding="utf-8"))
document["components"][1] = next(
    component for component in samples["components"]
    if component["name"] == "sentence-transformers/all-MiniLM-L6-v2"
)
Path("presentation/output/live-sbom.json").write_text(
    json.dumps(document, indent=2) + "\n", encoding="utf-8",
)
PY
uv run --locked sbom-reviewer review presentation/output/live-sbom.json --policy policy/licenses.json --fetch-model-cards --save-review presentation/output/live.sqlite
uv run --locked sbom-reviewer export presentation/output/live.sqlite --output presentation/output/07-live-card.html
```

The CLI selects the SBOM's model-card reference, normalizes it to raw README
Markdown, fetches sequentially with a 5-second socket timeout and 1 MiB limit,
then parses and applies policy. It rejects redirects and unsupported sources.
Only model components are fetched; linked terms are not recursively visited.

Live contents and availability can change. Inspect `model_assessment.status`:
`inspected` means a card was read; `unavailable` means it was not. Fetch failures
are component findings and still produce a complete review with exit 0. The
synthetic restriction passage from the offline fixture is not evidence about MiniLM.

## Implementation points to explain

- SBOM adapter → optional card fetch → pure evidence parser → pure policy → JSON
  machine review. Saving is optional and happens after that review is built.
- `model_cards.py` extracts metadata and excerpts; `policy.py` combines that
  evidence with declarations. No runtime AI or interpretation of arbitrary legal text.
- `storage.py` preserves the machine snapshot and appends events; `decisions.py`
  validates actions and derives current human decisions and counts.
- `report.py` renders saved data into escaped, standalone HTML. It performs no
  fetching and does not execute Markdown/HTML from the evidence.
- Reviewer names are caller-supplied, without authentication. Append-only behavior
  is an application guarantee, not protection against direct SQLite edits.
