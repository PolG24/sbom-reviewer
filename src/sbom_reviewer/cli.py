"""Command-line entry point for the SBOM reviewer."""

import argparse
from pathlib import Path

from sbom_reviewer.policy import load_policy, review_components
from sbom_reviewer.sbom import load_sbom


def build_parser() -> argparse.ArgumentParser:
    """Build the command-line parser."""
    parser = argparse.ArgumentParser(
        prog="sbom-reviewer",
        description="Review Software Bills of Materials for legal and license risks.",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    review = commands.add_parser("review", help="Review a CycloneDX JSON 1.6 SBOM against a local license policy.")
    review.add_argument("sbom", type=Path, help="Path to the CycloneDX JSON 1.6 SBOM.")
    review.add_argument("--policy", type=Path, required=True, help="Path to the local JSON license policy.")
    return parser


def main() -> None:
    """Emit a complete JSON review, or an actionable input error (exit 2)."""
    parser = build_parser()
    args = parser.parse_args()
    try:
        policy = load_policy(args.policy)
    except (OSError, ValueError) as exc:
        parser.error(f"Cannot load policy '{args.policy}': {exc}")
    try:
        components = load_sbom(args.sbom)
    except (OSError, ValueError) as exc:
        parser.error(f"Cannot review SBOM '{args.sbom}': {exc}")
    result = review_components(components, policy)
    print(result.model_dump_json(indent=2))


if __name__ == "__main__":
    main()
