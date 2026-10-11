"""Shared JSON parsing rules for untrusted SBOM and policy inputs."""

import json
from typing import Any, NoReturn


MAX_JSON_DEPTH = 128
NESTING_ERROR = f"JSON nesting exceeds the limit of {MAX_JSON_DEPTH} object/array levels; reduce input nesting."


def reject_numeric_constant(value: str) -> NoReturn:
    raise ValueError(f"Invalid JSON numeric constant {value!r}: use a finite JSON number.")


def parse_json(text: str) -> Any:
    try:
        document = json.loads(text, parse_constant=reject_numeric_constant)
    except RecursionError as exc:
        raise ValueError(NESTING_ERROR) from exc
    check_nesting(document)
    return document


def check_nesting(document: Any) -> None:
    """Check container depth iteratively before recursive library processing."""
    stack: list[tuple[Any, int]] = [(document, 1)]
    while stack:
        value, depth = stack.pop()
        if not isinstance(value, (dict, list)):
            continue
        if depth > MAX_JSON_DEPTH:
            raise ValueError(NESTING_ERROR)
        children = value.values() if isinstance(value, dict) else value
        stack.extend((child, depth + 1) for child in children if isinstance(child, (dict, list)))
