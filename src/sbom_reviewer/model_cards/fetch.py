"""Bounded retrieval of supported public Hugging Face Markdown cards."""

import hashlib
import re
import urllib.request
from dataclasses import dataclass
from email.message import Message
from http.client import HTTPException
from typing import BinaryIO
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit

from sbom_reviewer.models import FindingCode


@dataclass(frozen=True)
class FetchedCard:
    document_url: str
    text: str
    document_sha256: str


class CardFetchError(Exception):
    def __init__(self, code: FindingCode, message: str) -> None:
        super().__init__(message)
        self.code = code


def normalize_model_card_url(url: str) -> str:
    """Accept only the story's repository/card forms; reject URL parser repairs."""
    unsupported = CardFetchError(FindingCode.UNSUPPORTED_SOURCE, "Unsupported model-card source; use a public HTTPS Hugging Face repository or README card URL.")
    if re.search(r"\s", url) or "?" in url or "#" in url:
        raise unsupported
    try:
        parsed = urlsplit(url)
        valid = (parsed.scheme == "https" and parsed.hostname == "huggingface.co"
                 and parsed.username is None and parsed.password is None
                 and parsed.port in {None, 443})
    except ValueError as exc:
        raise unsupported from exc
    if not valid or parsed.netloc.lower() not in {"huggingface.co", "huggingface.co:443"}:
        raise unsupported
    parts = parsed.path.split("/")[1:]
    if len(parts) == 2:
        owner, repo = parts
        revision = "main"
    elif len(parts) == 5 and parts[2] in {"blob", "raw"} and parts[4] == "README.md":
        owner, repo, _, revision, _ = parts
    else:
        raise unsupported
    if owner in {"spaces", "datasets", "models", "organizations", "api", "docs", "blog",
                 "collections", "settings", "tasks", "papers", "learn"}:
        raise unsupported
    if any(segment in {".", ".."} or not re.fullmatch(r"[A-Za-z0-9._-]+", segment)
           for segment in (owner, repo, revision)):
        raise unsupported
    return f"https://huggingface.co/{owner}/{repo}/raw/{revision}/README.md"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: urllib.request.Request, fp: BinaryIO, code: int,
                         msg: str, headers: Message, newurl: str) -> None:
        return None


def fetch_model_card(url: str) -> FetchedCard:
    document_url = normalize_model_card_url(url)
    opener = urllib.request.build_opener(_NoRedirect())
    try:
        with opener.open(document_url, timeout=5) as response:
            content_type = response.headers.get_content_type()
            if content_type not in {"text/plain", "text/markdown", "text/x-markdown", "application/octet-stream"}:
                raise CardFetchError(FindingCode.UNAVAILABLE_SOURCE, f"Unsupported response type {content_type}; expected UTF-8 Markdown text.")
            body = response.read(1048576 + 1)
    except HTTPError as exc:
        problem = "Redirect rejected" if 300 <= exc.code < 400 else "HTTP error"
        raise CardFetchError(FindingCode.UNAVAILABLE_SOURCE, f"{problem} ({exc.code}) retrieving model card.") from exc
    except (TimeoutError, URLError, OSError, HTTPException) as exc:
        timeout = isinstance(exc, TimeoutError) or isinstance(getattr(exc, "reason", None), TimeoutError)
        problem = "Network timeout" if timeout else "Network connection failure"
        raise CardFetchError(FindingCode.UNAVAILABLE_SOURCE, f"{problem} retrieving model card.") from exc
    if len(body) > 1048576:
        raise CardFetchError(FindingCode.UNAVAILABLE_SOURCE, "Model card exceeds the 1 MiB response limit.")
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CardFetchError(FindingCode.UNAVAILABLE_SOURCE, "Model card is not valid UTF-8 text.") from exc
    if re.match(r"\s*(?:<!doctype\s+html|<html\b|<head\b|<body\b)", text.lstrip("\ufeff"), re.IGNORECASE):
        raise CardFetchError(FindingCode.UNAVAILABLE_SOURCE, "HTML response rejected; expected Markdown text.")
    return FetchedCard(document_url, text, hashlib.sha256(body).hexdigest())
