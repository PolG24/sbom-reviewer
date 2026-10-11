"""Small loopback-only browser adapter over the existing reviewer APIs."""

from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import secrets
import threading
from typing import Literal
from urllib.parse import unquote, urlsplit
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, ValidationError

from sbom_reviewer.json_input import parse_json
from sbom_reviewer.models import Policy
from sbom_reviewer.policy import load_policy
from sbom_reviewer.review import review_components
from sbom_reviewer.saved_reviews.decisions import DecisionError
from sbom_reviewer.saved_reviews.report import render_report
from sbom_reviewer.saved_reviews.storage import StorageError, load_review, record_decision, save_review
from sbom_reviewer.sbom import load_sbom


MAX_REQUEST_BYTES = 64 * 1024
_ASSETS = Path(__file__).parent


class UIError(ValueError):
    """An actionable local UI configuration or request failure."""


class RequestTooLarge(UIError):
    """The mutation body exceeds the local API limit."""

    status = 413


class ReviewRequest(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")
    sbom: str
    fetch_model_cards: bool = False


class DecisionRequest(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")
    component_id: str
    action: Literal["confirm", "override"]
    reviewer: str
    reason: str
    outcome: str | None = None


def _confined_file(directory: Path, name: str, suffix: str) -> Path:
    if not name or name in {".", ".."} or "/" in name or "\\" in name or "\x00" in name:
        raise UIError("Choose a listed filename, without a directory or path.")
    if Path(name).suffix != suffix:
        raise UIError(f"Choose a {suffix} file.")
    try:
        candidate = (directory / name).resolve()
    except (OSError, RuntimeError) as exc:
        raise UIError("The selected file is unavailable or has a symlink loop.") from exc
    if not candidate.is_relative_to(directory) or not candidate.is_file():
        raise UIError("The selected file is unavailable or outside the configured directory.")
    return candidate


def _files(directory: Path, suffix: str) -> list[str]:
    names: list[str] = []
    for path in directory.iterdir():
        if path.suffix != suffix:
            continue
        try:
            _confined_file(directory, path.name, suffix)
        except (UIError, OSError):
            continue
        names.append(path.name)
    return sorted(names)


class ReviewServer(ThreadingHTTPServer):
    """Own local configuration and serialize review mutations for this process."""

    daemon_threads = True

    def __init__(self, sbom_dir: Path, policy: Policy, review_dir: Path, port: int) -> None:
        self.sbom_dir = sbom_dir
        self.policy = policy
        self.review_dir = review_dir
        self.token = secrets.token_urlsafe(32)
        self.mutation_lock = threading.Lock()
        super().__init__(("127.0.0.1", port), ReviewHandler)

    def review_payload(self, name: str) -> dict:
        path = _confined_file(self.review_dir, name, ".sqlite")
        return {"id": name, "review": load_review(path).model_dump(mode="json")}


class ReviewHandler(BaseHTTPRequestHandler):
    server: ReviewServer

    def log_message(self, format: str, *args: object) -> None:
        # Request data is untrusted, and the CLI only needs to print its launch URL.
        pass

    def _send(self, status: int, body: str | bytes | dict, content_type: str = "application/json", *, download: bool = False) -> None:
        if isinstance(body, dict):
            body = json.dumps(body, ensure_ascii=True)
        data = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(status)
        self.send_header("Content-Type", content_type + "; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        if download:
            self.send_header("Content-Disposition", 'attachment; filename="sbom-review-report.html"')
        self.end_headers()
        self.wfile.write(data)

    def _authorized(self, mutation: bool) -> bool:
        hosts = {f"127.0.0.1:{self.server.server_port}", f"localhost:{self.server.server_port}"}
        if self.headers.get("Host") not in hosts:
            self._send(403, {"error": "Open the UI using its printed local URL."})
            return False
        if mutation:
            origin = self.headers.get("Origin")
            if origin is not None and origin not in {f"http://{host}" for host in hosts}:
                self._send(403, {"error": "Requests from another site are not permitted."})
                return False
            supplied_token = self.headers.get("X-Review-Token", "")
            if not supplied_token.isascii() or not secrets.compare_digest(supplied_token, self.server.token):
                self._send(403, {"error": "Reload the page to renew the local review session."})
                return False
        return True

    def _error(self, exc: Exception) -> None:
        if isinstance(exc, StorageError):
            message = "Cannot access the saved review. Check that the file is a valid review and is writable and not locked."
        elif isinstance(exc, ValidationError):
            message = "Invalid request fields or types. Select a file/action and supply reviewer and rationale as text."
        elif isinstance(exc, OSError):
            message = "Cannot access configured files. Check local directory permissions."
        else:
            message = str(exc)
            for directory in (self.server.sbom_dir, self.server.review_dir):
                message = message.replace(str(directory), "[configured directory]")
        self._send(getattr(exc, "status", 400), {"error": message})

    def do_GET(self) -> None:
        if not self._authorized(False):
            return
        try:
            path = unquote(urlsplit(self.path).path)
            assets = {"/": ("index.html", "text/html"), "/app.js": ("app.js", "text/javascript"), "/style.css": ("style.css", "text/css")}
            if path in assets:
                name, kind = assets[path]
                self._send(200, (_ASSETS / name).read_bytes(), kind)
            elif path == "/api/config":
                self._send(200, {"token": self.server.token, "sboms": _files(self.server.sbom_dir, ".json"),
                                 "reviews": _files(self.server.review_dir, ".sqlite"), "policy_version": self.server.policy.version})
            elif path.startswith("/api/reviews/"):
                parts = path.removeprefix("/api/reviews/").split("/")
                if len(parts) == 1:
                    self._send(200, self.server.review_payload(parts[0]))
                elif len(parts) == 2 and parts[1] == "report":
                    saved = load_review(_confined_file(self.server.review_dir, parts[0], ".sqlite"))
                    self._send(200, render_report(saved), "text/html", download=True)
                else:
                    self._send(404, {"error": "Unknown local UI route."})
            else:
                self._send(404, {"error": "Unknown local UI route."})
        except (ValueError, OSError, StorageError) as exc:
            self._error(exc)

    def _json_body(self) -> object:
        if self.headers.get_content_type() != "application/json" or self.headers.get("Transfer-Encoding"):
            raise UIError("Send a JSON request with a Content-Length header.")
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError as exc:
            raise UIError("A valid request length is required.") from exc
        if length < 0:
            raise UIError("A valid request length is required.")
        if length > MAX_REQUEST_BYTES:
            raise RequestTooLarge("Request is too large. Keep rationale below 64 KiB.")
        body = self.rfile.read(length)
        if len(body) != length:
            raise UIError("Incomplete JSON request.")
        return parse_json(body.decode("utf-8"))

    def do_POST(self) -> None:
        if not self._authorized(True):
            return
        try:
            body = self._json_body()
            path = unquote(urlsplit(self.path).path)
            with self.server.mutation_lock:
                if path == "/api/reviews":
                    data = ReviewRequest.model_validate(body)
                    sbom = _confined_file(self.server.sbom_dir, data.sbom, ".json")
                    result = review_components(load_sbom(sbom), self.server.policy, fetch_model_cards=data.fetch_model_cards)
                    name = datetime.now(timezone.utc).strftime("review-%Y%m%d-%H%M%S-") + uuid4().hex[:12] + ".sqlite"
                    save_review(self.server.review_dir / name, result)
                    self._send(201, self.server.review_payload(name))
                elif path.startswith("/api/reviews/") and path.endswith("/decisions"):
                    name = path.removeprefix("/api/reviews/").removesuffix("/decisions")
                    database = _confined_file(self.server.review_dir, name, ".sqlite")
                    data = DecisionRequest.model_validate(body)
                    if (data.action == "confirm" and data.outcome is not None) or (data.action == "override" and data.outcome is None):
                        raise UIError("Confirm has no override outcome; override requires a different outcome.")
                    record_decision(database, data.component_id, reviewer=data.reviewer, reason=data.reason,
                                    confirm=data.action == "confirm", override=data.outcome)
                    self._send(200, self.server.review_payload(name))
                else:
                    self._send(404, {"error": "Unknown local UI route."})
        except (ValueError, OSError, StorageError, DecisionError) as exc:
            self._error(exc)


def create_server(sbom_dir: Path, policy_path: Path, review_dir: Path, *, port: int = 8765) -> ReviewServer:
    """Validate local settings, then bind loopback; port zero selects a test port."""
    if isinstance(port, bool) or not isinstance(port, int) or not 0 <= port <= 65535:
        raise UIError("Port must be between 0 and 65535 (0 chooses a free local port).")
    sbom_dir = sbom_dir.resolve()
    if not sbom_dir.is_dir():
        raise UIError("SBOM directory does not exist or is not a directory.")
    try:
        policy = load_policy(policy_path)
    except (OSError, ValueError) as exc:
        raise UIError(f"Cannot load policy: {exc}") from exc
    try:
        review_dir.mkdir(parents=True, exist_ok=True)
        if not review_dir.is_dir():
            raise UIError("Review directory is not a directory.")
        review_dir = review_dir.resolve()
        # Verify write access now rather than on the first presentation action.
        probe = review_dir / (".ui-write-check-" + uuid4().hex)
        with probe.open("xb"):
            pass
        probe.unlink()
    except OSError as exc:
        raise UIError(f"Cannot use review directory: {exc}") from exc
    try:
        return ReviewServer(sbom_dir, policy, review_dir, port)
    except OSError as exc:
        raise UIError(f"Cannot start local UI on port {port}: {exc}. Try --port with another port.") from exc


def run_ui(sbom_dir: Path, policy_path: Path, review_dir: Path, *, port: int = 8765) -> None:
    """Print the browser URL and serve until interrupted."""
    if not 1 <= port <= 65535:
        raise UIError("Port must be between 1 and 65535.")
    with create_server(sbom_dir, policy_path, review_dir, port=port) as server:
        print(f"SBOM reviewer UI: http://127.0.0.1:{server.server_port}/", flush=True)
        print("Press Ctrl-C to stop.", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
