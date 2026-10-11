"""Exercise retrieval validation and bounds with only the HTTP boundary replaced."""

import hashlib
import io
from email.message import Message
from urllib.error import HTTPError, URLError
from urllib.request import Request
from urllib.response import addinfourl

import pytest


def fetch_module():
    from sbom_reviewer import model_card_fetch
    assert hasattr(model_card_fetch, "fetch_model_card"), "Bounded retrieval is not implemented"
    return model_card_fetch


@pytest.mark.parametrize("url, expected", [
    ("https://huggingface.co/owner/repo", "https://huggingface.co/owner/repo/raw/main/README.md"),
    ("https://huggingface.co:443/Owner/repo-1.2", "https://huggingface.co/Owner/repo-1.2/raw/main/README.md"),
    ("https://huggingface.co/o/r/blob/v1_0/README.md", "https://huggingface.co/o/r/raw/v1_0/README.md"),
    ("https://huggingface.co/o/r/raw/abc123/README.md", "https://huggingface.co/o/r/raw/abc123/README.md"),
])
def test_supported_urls_normalize_to_markdown(url: str, expected: str) -> None:
    module = fetch_module()
    assert module.normalize_model_card_url(url) == expected


@pytest.mark.parametrize("url", [
    "http://huggingface.co/o/r", "https://example.org/o/r", "https://huggingface.co.evil/o/r",
    "https://www.huggingface.co/o/r", "https://user@huggingface.co/o/r",
    "https://user:secret@huggingface.co/o/r", "https://huggingface.co:444/o/r",
    "https://huggingface.co:bad/o/r", "https://huggingface.co/o/r?x=y", "https://huggingface.co/o/r#license",
    "https://huggingface.co/o/r?", "https://huggingface.co/o/r#", "https://huggingface.co/o/r/",
    "https://huggingface.co/spaces/repo", "https://huggingface.co/datasets/repo",
    "https://huggingface.co/models/repo", "https://huggingface.co/organizations/repo",
    "https://huggingface.co/o", "https://huggingface.co/o/r/resolve/main/README.md",
    "https://huggingface.co/o/r/blob/main/LICENSE", "https://huggingface.co/o/r/blob/a/b/README.md",
    "https://huggingface.co/o/r/blob/../README.md", "https://huggingface.co/./r",
    "https://huggingface.co/o/..", "https://huggingface.co/o/%72", "https://huggingface.co/o/r/blob/%61/README.md",
    "https://huggingface.co/o/r/blob//README.md", "https://huggingface.co/o/r/raw/main/readme.md",
    "https://huggingface.co/o\\r", "https://huggingface.co/o/r\n", "https://huggingface.co//o/r",
    "https://huggingface.co/[bad", "https://[huggingface.co/o/r",
])
def test_unsupported_urls_never_open_http(monkeypatch, url: str) -> None:
    module = fetch_module()
    def unexpected(*args, **kwargs):
        pytest.fail("Unsupported references must not open an HTTP client")
    monkeypatch.setattr(module.urllib.request, "build_opener", unexpected)
    with pytest.raises(module.CardFetchError) as caught:
        module.fetch_model_card(url)
    assert caught.value.code == "unsupported_source"


class Response(io.BytesIO):
    def __init__(self, body: bytes, content_type: str = "text/plain; charset=utf-8") -> None:
        super().__init__(body)
        self.headers = Message()
        self.headers["Content-Type"] = content_type
        self.sizes: list[int] = []

    def read(self, size: int = -1) -> bytes:
        self.sizes.append(size)
        return super().read(size)


def boundary(monkeypatch, module, response: Response | Exception):
    calls: list[tuple[str, float]] = []
    class Opener:
        def open(self, request, timeout):
            url = request.full_url if isinstance(request, Request) else request
            calls.append((url, timeout))
            if isinstance(response, Exception):
                raise response
            return response
    monkeypatch.setattr(module.urllib.request, "build_opener", lambda *handlers: Opener())
    return calls


def test_fetch_records_raw_byte_hash_and_bounded_read(monkeypatch) -> None:
    module = fetch_module()
    body = b"---\r\nlicense: mit\r\n---\r\n# Synthetic \xc3\xa9\r\n"
    response = Response(body)
    calls = boundary(monkeypatch, module, response)
    card = module.fetch_model_card("https://huggingface.co/o/r")
    assert card.text == body.decode("utf-8")
    assert card.document_sha256 == hashlib.sha256(body).hexdigest()
    assert card.document_url == "https://huggingface.co/o/r/raw/main/README.md"
    assert calls == [(card.document_url, 5)]
    assert response.sizes == [1048577]


@pytest.mark.parametrize("body, content_type", [
    (b"<html>Login</html>", "text/html"), (b" \n<!DOCTYPE html><html>oops", "text/plain"),
    (b"<HTML>oops", "application/octet-stream"), (b"\xff", "text/plain"),
    (b"{}", "application/json"), (b"pdf", "application/pdf"),
    (b"x" * 1048577, "text/plain"),
], ids=["html-type", "html-sniff", "html-octets", "invalid-utf8", "json", "pdf", "oversized"])
def test_unreadable_and_oversized_responses_are_retrieval_findings(monkeypatch, body: bytes, content_type: str) -> None:
    module = fetch_module()
    boundary(monkeypatch, module, Response(body, content_type))
    with pytest.raises(module.CardFetchError) as caught:
        module.fetch_model_card("https://huggingface.co/o/r")
    assert caught.value.code == "unavailable_source"
    assert str(caught.value)


def test_exact_response_limit_is_accepted(monkeypatch) -> None:
    module = fetch_module()
    boundary(monkeypatch, module, Response(b"a" * 1048576))
    assert len(module.fetch_model_card("https://huggingface.co/o/r").text) == 1048576


@pytest.mark.parametrize("error, word", [
    (HTTPError("https://huggingface.co/o/r", 404, "Not found", Message(), None), "404"),
    (HTTPError("https://huggingface.co/o/r", 503, "Busy", Message(), None), "503"),
    (TimeoutError("slow"), "timeout"), (URLError(TimeoutError("slow")), "timeout"),
    (URLError("connection refused"), "connection"), (ConnectionResetError("reset"), "connection"),
])
def test_network_failures_are_wrapped_without_retries(monkeypatch, error: Exception, word: str) -> None:
    module = fetch_module()
    calls = boundary(monkeypatch, module, error)
    with pytest.raises(module.CardFetchError) as caught:
        module.fetch_model_card("https://huggingface.co/o/r")
    assert caught.value.code == "unavailable_source"
    assert word in str(caught.value).lower()
    assert len(calls) == 1


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
def test_redirects_are_blocked_by_real_urllib_handler(monkeypatch, status: int) -> None:
    module = fetch_module()
    def https_response(handler, request):
        headers = Message()
        headers["Location"] = "https://example.org/secret"
        response = addinfourl(io.BytesIO(), headers, request.full_url, status)
        response.msg = "Redirect"
        return response
    monkeypatch.setattr(module.urllib.request.HTTPSHandler, "https_open", https_response)
    with pytest.raises(module.CardFetchError) as caught:
        module.fetch_model_card("https://huggingface.co/o/r")
    assert caught.value.code == "unavailable_source"
    assert "redirect" in str(caught.value).lower()


def test_programming_errors_are_not_disguised_as_source_failures(monkeypatch) -> None:
    module = fetch_module()
    boundary(monkeypatch, module, RuntimeError("programming mistake"))
    with pytest.raises(RuntimeError, match="programming mistake"):
        module.fetch_model_card("https://huggingface.co/o/r")


@pytest.mark.parametrize("resource", ["api", "docs", "blog", "collections", "settings", "tasks", "papers", "learn"])
def test_other_hub_resources_are_not_model_repositories(monkeypatch, resource: str) -> None:
    module = fetch_module()
    def fail(*args, **kwargs):
        pytest.fail("Other Hub resources must not be fetched as model repositories")
    monkeypatch.setattr(module.urllib.request, "build_opener", fail)
    with pytest.raises(module.CardFetchError) as caught:
        module.fetch_model_card(f"https://huggingface.co/{resource}/page")
    assert caught.value.code == "unsupported_source"


def test_host_case_is_insensitive_without_accepting_other_hosts() -> None:
    module = fetch_module()
    assert module.normalize_model_card_url("https://HuggingFace.co/o/r") == "https://huggingface.co/o/r/raw/main/README.md"
