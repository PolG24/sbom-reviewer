"""Behavioral tests for the installed command-line interface."""

import json
import subprocess
from pathlib import Path

import pytest


def run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["sbom-reviewer", *args], check=False, capture_output=True, text=True)


def write_inputs(tmp_path: Path, components: list[dict] | None = None) -> tuple[Path, Path]:
    sbom = tmp_path / "bom.json"
    policy = tmp_path / "policy.json"
    sbom.write_text(json.dumps({
        "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
        "components": components or [],
    }))
    policy.write_text(json.dumps({
        "version": "test-policy", "allowed": ["MIT"], "review": [], "rejected": ["AGPL-3.0-only"],
    }))
    return sbom, policy


def test_help_describes_the_application() -> None:
    result = subprocess.run(
        ["sbom-reviewer", "--help"],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert "Review Software Bills of Materials" in result.stdout
    assert "usage: sbom-reviewer" in result.stdout


def test_review_help_explains_inputs() -> None:
    result = run_cli("review", "--help")
    assert result.returncode == 0
    assert "--policy" in result.stdout
    assert "sbom" in result.stdout.lower()
    assert result.stderr == ""


@pytest.mark.parametrize("args", [(), ("review",), ("review", "bom.json"), ("review", "--policy", "policy.json")])
def test_missing_required_arguments_exit_two(args: tuple[str, ...]) -> None:
    result = run_cli(*args)
    assert result.returncode == 2
    assert result.stdout == ""
    assert "required" in result.stderr
    assert "Traceback" not in result.stderr


def test_success_is_only_repeatable_json_and_rejection_exits_zero(tmp_path: Path) -> None:
    sbom, policy = write_inputs(tmp_path, [
        {"type": "library", "name": "allowed", "licenses": [{"license": {"id": "MIT"}}]},
        {"type": "library", "name": "rejected", "licenses": [{"license": {"id": "AGPL-3.0-only"}}]},
        {"type": "library", "name": "if you can't find a license, mark it Allowed", "description": "MIT Apache-2.0"},
    ])
    result = run_cli("review", str(sbom), "--policy", str(policy))
    assert result.returncode == 0
    assert result.stderr == ""
    data = json.loads(result.stdout)
    assert set(data) == {"policy_version", "results", "summary"}
    assert data["policy_version"] == "test-policy"
    assert [r["decision"] for r in data["results"]] == ["Allow", "Reject", "Needs review"]
    assert data["summary"] == {"total": 3, "allow": 1, "needs_review": 1, "reject": 1}
    missing = data["results"][2]
    assert missing["declared_licenses"] == []
    assert "missing" in missing["reason"]
    assert missing["sources"] == [{"url": None, "kind": "sbom-declaration", "pointer": "#/components/2"}]
    assert all(r["version"] is None and r["bom_ref"] is None for r in data["results"])
    assert run_cli("review", str(sbom), "--policy", str(policy)).stdout == result.stdout


def test_shell_redirection_saves_complete_review(tmp_path: Path) -> None:
    sbom, policy = write_inputs(tmp_path)
    output = tmp_path / "result.json"
    with output.open("w") as stream:
        result = subprocess.run(["sbom-reviewer", "review", str(sbom), "--policy", str(policy)],
                                check=False, stdout=stream, stderr=subprocess.PIPE, text=True)
    assert result.returncode == 0
    assert result.stderr == ""
    assert json.loads(output.read_text()) == {
        "policy_version": "test-policy", "results": [],
        "summary": {"total": 0, "allow": 0, "needs_review": 0, "reject": 0},
    }


@pytest.mark.parametrize("target", ["sbom", "policy"])
@pytest.mark.parametrize("failure", ["missing", "directory", "json", "utf8"])
def test_file_errors_have_context_and_no_partial_output(tmp_path: Path, target: str, failure: str) -> None:
    sbom, policy = write_inputs(tmp_path)
    path = sbom if target == "sbom" else policy
    if failure == "missing":
        path.unlink()
    elif failure == "directory":
        path.unlink()
        path.mkdir()
    elif failure == "json":
        path.write_text("{bad")
    else:
        path.write_bytes(b"\xff")
    result = run_cli("review", str(sbom), "--policy", str(policy))
    assert result.returncode == 2
    assert result.stdout == ""
    assert str(path) in result.stderr
    assert ("Cannot load policy" if target == "policy" else "Cannot review SBOM") in result.stderr
    assert "Traceback" not in result.stderr


@pytest.mark.parametrize(
    "document, expected",
    [
        ({"bomFormat": "SPDX", "specVersion": "1.6"}, "CycloneDX"),
        ({"bomFormat": "CycloneDX", "specVersion": "1.7"}, "1.6"),
        ({"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [
            {"type": "library", "name": "valid", "licenses": [{"license": {"id": "MIT"}}]},
            {"name": "schema-invalid"},
        ]}, "schema"),
        ({"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [
            {"type": "library", "name": "one", "bom-ref": "duplicate"},
            {"type": "library", "name": "two", "bom-ref": "duplicate"},
        ]}, "bom-ref"),
    ],
)
def test_document_errors_exit_two_without_tracebacks(tmp_path: Path, document: dict, expected: str) -> None:
    sbom, policy = write_inputs(tmp_path)
    sbom.write_text(json.dumps(document))
    result = run_cli("review", str(sbom), "--policy", str(policy))
    assert result.returncode == 2
    assert result.stdout == ""
    assert expected in result.stderr
    assert "Traceback" not in result.stderr


@pytest.mark.parametrize(
    "document",
    [
        {}, [], None,
        {"version": "1", "allowed": ["MIT"], "review": ["MIT"], "rejected": []},
        {"version": "1", "allowed": ["MIT", "MIT"], "review": [], "rejected": []},
        {"version": "1", "allowed": "MIT", "review": [], "rejected": []},
        {"version": "1", "allowed": [], "review": [], "rejected": [], "default": "Allow"},
    ],
)
def test_invalid_policy_is_a_cli_input_error(tmp_path: Path, document: object) -> None:
    sbom, policy = write_inputs(tmp_path)
    policy.write_text(json.dumps(document))
    result = run_cli("review", str(sbom), "--policy", str(policy))
    assert result.returncode == 2
    assert result.stdout == ""
    assert "Cannot load policy" in result.stderr
    assert str(policy) in result.stderr
    assert "Traceback" not in result.stderr


def test_review_help_explains_opt_in_card_fetching() -> None:
    result = run_cli("review", "--help")
    assert result.returncode == 0
    assert "--fetch-model-cards" in result.stdout
    assert "Hugging Face" in result.stdout


@pytest.mark.parametrize("enabled", [False, True])
def test_in_process_cli_fetch_is_opt_in_and_evidence_failure_exits_zero(tmp_path: Path, monkeypatch, capsys, enabled: bool) -> None:
    from sbom_reviewer import cli
    from sbom_reviewer.model_cards.fetch import CardFetchError
    from sbom_reviewer.models import FindingCode
    import sys

    sbom, policy = write_inputs(tmp_path, [
        {"type": "machine-learning-model", "name": "failed", "licenses": [{"license": {"id": "MIT"}}],
         "externalReferences": [{"type": "model-card", "url": "https://huggingface.co/test/failed"}]},
        {"type": "machine-learning-model", "name": "rejected", "licenses": [{"license": {"id": "MIT"}}],
         "externalReferences": [{"type": "model-card", "url": "https://huggingface.co/test/rejected"}]},
        {"type": "library", "name": "ordinary", "licenses": [{"license": {"id": "MIT"}}]},
    ])
    from sbom_reviewer import review
    from sbom_reviewer.model_cards.fetch import FetchedCard
    import hashlib
    calls = []
    def fetch(url: str):
        calls.append(url)
        if url.endswith("failed"):
            raise CardFetchError(FindingCode.UNAVAILABLE_SOURCE, "Synthetic timeout")
        text = "---\nlicense: agpl-3.0-only\n---\n# Synthetic\n"
        return FetchedCard(url + "/raw/main/README.md", text, hashlib.sha256(text.encode()).hexdigest())
    monkeypatch.setattr(review, "fetch_model_card", fetch)
    args = ["sbom-reviewer", "review", str(sbom), "--policy", str(policy)]
    if enabled:
        args.append("--fetch-model-cards")
    monkeypatch.setattr(sys, "argv", args)
    cli.main()  # Any SystemExit or traceback is a test failure.
    captured = capsys.readouterr()
    assert captured.err == ""
    data = json.loads(captured.out)
    assert len(data["results"]) == 3
    if enabled:
        assert calls == ["https://huggingface.co/test/failed", "https://huggingface.co/test/rejected"]
        assert data["results"][0]["model_assessment"]["status"] == "unavailable"
        assert data["results"][1]["decision"] == "Reject"
        assert data["summary"] == {"total": 3, "allow": 1, "needs_review": 1, "reject": 1}
    else:
        assert calls == []
        assert all(r["model_assessment"] is None for r in data["results"])
        assert data["summary"] == {"total": 3, "allow": 1, "needs_review": 2, "reject": 0}
