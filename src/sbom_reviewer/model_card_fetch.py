"""Retrieved Markdown document contract for pure model-card inspection."""

from dataclasses import dataclass


@dataclass(frozen=True)
class FetchedCard:
    document_url: str
    text: str
    document_sha256: str
