"""Shared JSON parsing rules for untrusted SBOM and policy inputs."""

import json
from typing import Any, NoReturn


def reject_numeric_constant(value: str) -> NoReturn:
    raise ValueError(f"Invalid JSON numeric constant {value!r}: use a finite JSON number.")


def parse_json(text: str) -> Any:
    return json.loads(text, parse_constant=reject_numeric_constant)
