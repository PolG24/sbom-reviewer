"""Hand-specified acceptance expectations for the illustrative inventory."""

import json
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_sample_inventory_has_expected_findings_and_repeatable_json() -> None:
    args = ["sbom-reviewer", "review", str(ROOT / "samples/cyclonedx.json"), "--policy", str(ROOT / "policy/licenses.json")]
    result = subprocess.run(args, check=False, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert result.stderr == ""
    data = json.loads(result.stdout)
    # Derived from the story and the fixture's declarations, not classifier helpers.
    assert [(r["component_id"], r["name"], r["declared_licenses"], r["decision"]) for r in data["results"]] == [
        ("#/metadata/component", "illustrative-product", ["Apache-2.0"], "Allow"),
        ("#/components/0", "fast-parser", ["MIT"], "Allow"),
        ("#/components/1", "transport", ["Apache-2.0"], "Allow"),
        ("#/components/2", "codec", ["BSD-3-Clause"], "Allow"),
        ("#/components/3", "document-engine", ["MPL-2.0"], "Needs review"),
        ("#/components/4", "media-toolkit", ["LGPL-3.0-only"], "Needs review"),
        ("#/components/5", "collaboration-server", ["AGPL-3.0-only"], "Reject"),
        ("#/components/6", "tiny-helper", ["ISC"], "Needs review"),
        ("#/components/7", "commercial-plugin", ["Example Commercial License"], "Needs review"),
        ("#/components/8", "unidentified-module", [], "Needs review"),
        ("#/components/9", "dual-license-library", ["MIT OR Apache-2.0"], "Needs review"),
        ("#/components/10", "sentence-transformers/all-MiniLM-L6-v2", ["Apache-2.0"], "Needs review"),
        ("#/components/11", "BAAI/bge-small-en-v1.5", ["MIT"], "Needs review"),
        ("#/components/12", "bigscience/bloom-560m", ["BigScience RAIL License"], "Needs review"),
    ]
    assert data["policy_version"] == "1.0"
    assert data["summary"] == {"total": 14, "allow": 4, "needs_review": 9, "reject": 1}
    assert all(r["reason"] and r["sources"] for r in data["results"])
    missing = data["results"][9]
    assert missing["sources"] == [{"url": None, "kind": "sbom-declaration", "pointer": "#/components/8"}]
    for model, card_url in zip(data["results"][-3:-1], [
        "https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2",
        "https://huggingface.co/BAAI/bge-small-en-v1.5",
    ], strict=True):
        assert model["type"] == "machine-learning-model"
        assert "allowed" in model["reason"] and "model-card restrictions have not been checked" in model["reason"]
        assert any(s["kind"] == "model-card" and s["url"] == card_url for s in model["sources"])
    custom = data["results"][-1]
    assert "custom" in custom["reason"]
    assert any(source["url"] == "https://huggingface.co/bigscience/bloom-560m" and source["kind"] == "model-card" for source in custom["sources"])
    assert all(result["model_assessment"] is None for result in data["results"])
    again = subprocess.run(args, check=False, capture_output=True, text=True)
    assert again.returncode == 0
    assert again.stderr == ""
    assert again.stdout == result.stdout
