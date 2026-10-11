"""HTTP behavior of the local UI, using real review snapshots and SQLite."""

from contextlib import contextmanager
import hashlib
import http.client
import importlib.util
import json
from pathlib import Path
import threading

import pytest

from sbom_reviewer.saved_reviews.storage import load_review, save_review
from test_cli import run_cli, write_inputs


def server_factory():
    assert importlib.util.find_spec("sbom_reviewer.ui") is not None, "Local UI server is not implemented"
    from sbom_reviewer.ui import create_server
    return create_server


@contextmanager
def running(sbom_dir: Path, policy: Path, review_dir: Path):
    server = server_factory()(sbom_dir, policy, review_dir, port=0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def request(server, method: str, path: str, payload=None, headers=None):
    connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=10)
    body = json.dumps(payload).encode() if payload is not None else None
    supplied = {"Content-Type": "application/json"}
    if method == "POST":
        supplied["X-Review-Token"] = server.token
    supplied.update(headers or {})
    connection.request(method, path, body, supplied)
    response = connection.getresponse()
    raw = response.read()
    result = json.loads(raw) if "application/json" in response.getheader("Content-Type", "") else raw.decode()
    result_headers = dict(response.getheaders())
    status = response.status
    connection.close()
    return status, result, result_headers


def test_ui_help_documents_local_launch():
    result = run_cli("ui", "--help")
    assert result.returncode == 0
    assert "--sbom-dir" in result.stdout and "--review-dir" in result.stdout
    assert "--port" in result.stdout


def test_review_confirm_override_reopen_and_export(tmp_path, machine_review):
    sbom, policy = write_inputs(tmp_path, [
        {"name": "allowed", "type": "library", "licenses": [{"license": {"id": "MIT"}}]},
        {"name": "rejected", "type": "library", "licenses": [{"license": {"id": "AGPL-3.0-only"}}]},
        {"name": "missing", "type": "library"},
    ])
    output = tmp_path / "reviews"
    with running(tmp_path, policy, output) as server:
        status, config, _ = request(server, "GET", "/api/config")
        assert status == 200 and config["token"] == server.token
        assert "bom.json" in config["sboms"] and config["reviews"] == []
        status, created, _ = request(server, "POST", "/api/reviews", {"sbom": sbom.name, "fetch_model_cards": False})
        assert status == 201
        review_id = created["id"]
        snapshot = created["review"]["snapshot"]
        assert snapshot["summary"] == {"total": 3, "allow": 1, "needs_review": 1, "reject": 1}
        for component, action, outcome in [(1, "confirm", None), (2, "confirm", None), (1, "override", "Allow")]:
            payload = {"component_id": f"#/components/{component}", "action": action,
                       "reviewer": "Legal", "reason": "Checked original evidence"}
            if outcome is not None:
                payload["outcome"] = outcome
            status, updated, _ = request(server, "POST", f"/api/reviews/{review_id}/decisions", payload)
            assert status == 200
        saved = updated["review"]
        assert saved["snapshot"] == snapshot
        assert [event["decision"] for event in saved["audit_log"]] == ["Reject", "Needs review", "Allow"]
        assert saved["reviewer_summary"] == {"total": 3, "recorded": 2, "pending": 1,
                                            "allow": 1, "needs_review": 1, "reject": 0}
        before = (output / review_id).read_bytes()
        status, html, headers = request(server, "GET", f"/api/reviews/{review_id}/report")
        assert status == 200 and "attachment" in headers["Content-Disposition"]
        assert "Checked original evidence" in html and "Complete decision history" in html
        assert (output / review_id).read_bytes() == before
        status, fresh, _ = request(server, "POST", "/api/reviews", {"sbom": sbom.name})
        assert status == 201 and fresh["id"] != review_id
        assert fresh["review"]["audit_log"] == []
    with running(tmp_path, policy, output) as server:
        _, config, _ = request(server, "GET", "/api/config")
        assert review_id in config["reviews"]
        status, reopened, _ = request(server, "GET", f"/api/reviews/{review_id}")
        assert status == 200 and reopened["review"] == saved


@pytest.mark.parametrize("payload", [
    {"reviewer": " "}, {"reason": "\n"}, {"action": "delete"},
    {"component_id": "missing"}, {"action": "override", "outcome": "Allow"},
    {"action": "override", "outcome": "invalid"}, {"reviewer": 4},
    {"action": "confirm", "outcome": "Reject"}, {"reason": None},
])
def test_invalid_decisions_never_append_events(tmp_path, machine_review, payload):
    _, policy = write_inputs(tmp_path)
    output = tmp_path / "reviews"
    output.mkdir()
    save_review(output / "saved.sqlite", machine_review)
    with running(tmp_path, policy, output) as server:
        data = {"component_id": "#/components/0", "action": "confirm", "reviewer": "Legal", "reason": "Checked"}
        data.update(payload)
        status, body, _ = request(server, "POST", "/api/reviews/saved.sqlite/decisions", data)
        assert status == 400 and "error" in body
        assert load_review(output / "saved.sqlite").audit_log == []


@pytest.mark.parametrize("payload", [
    {"sbom": "../outside.json"}, {"sbom": "/etc/passwd"}, {"sbom": "missing.json"},
    {"sbom": "bom.json", "fetch_model_cards": "false"}, {"sbom": 4}, [],
])
def test_bad_review_request_creates_no_database(tmp_path, payload):
    _, policy = write_inputs(tmp_path)
    output = tmp_path / "reviews"
    with running(tmp_path, policy, output) as server:
        status, body, _ = request(server, "POST", "/api/reviews", payload)
        assert status in {400, 404} and "error" in body
        assert list(output.iterdir()) == []


def test_invalid_sbom_and_corrupt_saved_review_report_errors(tmp_path):
    sbom, policy = write_inputs(tmp_path)
    sbom.write_text("{broken")
    output = tmp_path / "reviews"
    with running(tmp_path, policy, output) as server:
        status, body, _ = request(server, "POST", "/api/reviews", {"sbom": "bom.json"})
        assert status == 400 and "error" in body
        assert list(output.iterdir()) == []
        (output / "broken.sqlite").write_text("broken")
        status, body, _ = request(server, "GET", "/api/reviews/broken.sqlite")
        assert status == 400 and "error" in body
        assert str(tmp_path) not in body["error"]


def test_escaping_symlinks_and_arbitrary_routes_are_refused(tmp_path, machine_review):
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    sbom, policy = write_inputs(inputs)
    outside, _ = write_inputs(tmp_path)
    (inputs / "escape.json").symlink_to(outside)
    (inputs / "nested").mkdir()
    output = tmp_path / "reviews"
    output.mkdir()
    save_review(tmp_path / "outside.sqlite", machine_review)
    (output / "escape.sqlite").symlink_to(tmp_path / "outside.sqlite")
    with running(inputs, policy, output) as server:
        _, config, _ = request(server, "GET", "/api/config")
        assert "escape.json" not in config["sboms"] and "escape.sqlite" not in config["reviews"]
        for method, path, payload in [
            ("POST", "/api/reviews", {"sbom": "escape.json"}),
            ("GET", "/api/reviews/escape.sqlite", None),
            ("GET", "/api/reviews/../outside.sqlite", None),
            ("GET", "/api/reviews/%2e%2e%2foutside.sqlite", None),
            ("GET", "/../../etc/passwd", None),
        ]:
            status, body, _ = request(server, method, path, payload)
            assert status in {400, 404} and "error" in body


@pytest.mark.parametrize("headers", [
    {"X-Review-Token": "wrong"}, {"Origin": "https://evil.example"},
    {"Origin": "null"}, {"Host": "evil.example"},
])
def test_cross_site_mutations_are_rejected(tmp_path, headers):
    _, policy = write_inputs(tmp_path)
    output = tmp_path / "reviews"
    with running(tmp_path, policy, output) as server:
        status, body, _ = request(server, "POST", "/api/reviews", {"sbom": "bom.json"}, headers)
        assert status == 403 and "error" in body
        assert list(output.iterdir()) == []


def test_request_size_and_wrong_content_type_are_rejected(tmp_path):
    _, policy = write_inputs(tmp_path)
    with running(tmp_path, policy, tmp_path / "reviews") as server:
        status, _, _ = request(server, "POST", "/api/reviews", {"sbom": "x" * 70000})
        assert status == 413
        status, _, _ = request(server, "POST", "/api/reviews", {"sbom": "bom.json"}, {"Content-Type": "text/plain"})
        assert status == 400
        status, _, _ = request(server, "GET", "/api/config", headers={"Host": "evil.example"})
        assert status == 403


def test_fetch_is_opt_in_and_saved_model_evidence_survives_export(tmp_path, monkeypatch):
    from sbom_reviewer import review
    from sbom_reviewer.model_cards.fetch import FetchedCard
    sbom, policy = write_inputs(tmp_path, [{"type": "machine-learning-model", "name": "model",
        "externalReferences": [{"type": "model-card", "url": "https://huggingface.co/test/model"}]}])
    def fetch(url):
        assert url == "https://huggingface.co/test/model"
        text = "---\nlicense: mit\n---\n# License\nSynthetic evidence\n"
        return FetchedCard(url + "/raw/main/README.md", text, hashlib.sha256(text.encode()).hexdigest())
    monkeypatch.setattr(review, "fetch_model_card", lambda _: pytest.fail("Default UI fetched evidence"))
    with running(tmp_path, policy, tmp_path / "reviews") as server:
        status, default, _ = request(server, "POST", "/api/reviews", {"sbom": sbom.name})
        assert status == 201 and default["review"]["snapshot"]["results"][0]["model_assessment"] is None
        monkeypatch.setattr(review, "fetch_model_card", fetch)
        status, fetched, _ = request(server, "POST", "/api/reviews", {"sbom": sbom.name, "fetch_model_cards": True})
        assert status == 201
        component = fetched["review"]["snapshot"]["results"][0]
        assert component["model_assessment"]["status"] == "inspected"
        assert component["model_assessment"]["license_evidence"]["excerpt"] == "license: mit\n"
        monkeypatch.setattr(review, "fetch_model_card", lambda _: pytest.fail("Export fetched evidence"))
        status, html, _ = request(server, "GET", f'/api/reviews/{fetched["id"]}/report')
        assert status == 200 and "license: mit" in html


@pytest.mark.parametrize("option,value,match", [
    ("--sbom-dir", "missing", "directory"), ("--policy", "missing", "policy"),
    ("--review-dir", "bom.json", "directory"), ("--port", "-1", "port"),
    ("--port", "65536", "port"),
])
def test_ui_cli_reports_invalid_configuration_without_tracebacks(tmp_path, option, value, match):
    sbom, policy = write_inputs(tmp_path)
    args = ["ui", "--sbom-dir", str(tmp_path), "--policy", str(policy), "--review-dir", str(tmp_path / "reviews")]
    args.extend([option, value if option == "--port" else str(tmp_path / value)])
    result = run_cli(*args)
    assert result.returncode == 2 and result.stdout == ""
    assert match in result.stderr.lower() and "Traceback" not in result.stderr


def test_ui_serves_packaged_page_and_assets_with_local_security_headers(tmp_path):
    _, policy = write_inputs(tmp_path)
    with running(tmp_path, policy, tmp_path / "reviews") as server:
        for route, kind in [("/", "text/html"), ("/app.js", "text/javascript"), ("/style.css", "text/css")]:
            status, text, headers = request(server, "GET", route)
            assert status == 200 and text.strip()
            assert headers["Content-Type"].startswith(kind)
            assert headers["X-Content-Type-Options"] == "nosniff"
            assert "frame-ancestors 'none'" in headers["Content-Security-Policy"]
        status, body, _ = request(server, "POST", "/api/reviews", {"sbom": "bom.json"}, {"X-Review-Token": ""})
        assert status == 403 and "error" in body


def test_malformed_json_and_missing_request_length_get_clear_errors(tmp_path):
    _, policy = write_inputs(tmp_path)
    with running(tmp_path, policy, tmp_path / "reviews") as server:
        for raw in (b"{broken", b"null", b"NaN", b"\xff"):
            connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=3)
            connection.request("POST", "/api/reviews", raw,
                               {"Content-Type": "application/json", "X-Review-Token": server.token})
            response = connection.getresponse()
            assert response.status == 400 and "error" in json.loads(response.read())
            connection.close()
        connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=3)
        connection.putrequest("POST", "/api/reviews")
        connection.putheader("Content-Type", "application/json")
        connection.putheader("X-Review-Token", server.token)
        connection.endheaders()
        response = connection.getresponse()
        assert response.status == 400 and "error" in json.loads(response.read())
        connection.close()


def test_non_ascii_token_is_rejected_without_closing_response(tmp_path):
    _, policy = write_inputs(tmp_path)
    with running(tmp_path, policy, tmp_path / "reviews") as server:
        status, body, _ = request(server, "POST", "/api/reviews", {"sbom": "bom.json"}, {"X-Review-Token": "\xff"})
        assert status == 403 and "error" in body


def test_symlink_loops_do_not_break_listing_or_file_validation(tmp_path):
    _, policy = write_inputs(tmp_path)
    (tmp_path / "loop.json").symlink_to("loop.json")
    output = tmp_path / "reviews"
    output.mkdir()
    (output / "loop.sqlite").symlink_to("loop.sqlite")
    with running(tmp_path, policy, output) as server:
        status, config, _ = request(server, "GET", "/api/config")
        assert status == 200
        assert "loop.json" not in config["sboms"] and "loop.sqlite" not in config["reviews"]
        status, body, _ = request(server, "POST", "/api/reviews", {"sbom": "loop.json"})
        assert status == 400 and "error" in body
        status, body, _ = request(server, "GET", "/api/reviews/loop.sqlite")
        assert status == 400 and "error" in body
