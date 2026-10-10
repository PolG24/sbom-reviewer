"""Command-line entry point for the SBOM reviewer."""

import argparse


def build_parser() -> argparse.ArgumentParser:
    """Build the command-line parser."""
    parser = argparse.ArgumentParser(
        prog="sbom-reviewer",
        description="Review Software Bills of Materials for legal and license risks.",
    )
    return parser


def main() -> None:
    """Parse command-line arguments."""
    build_parser().parse_args()


if __name__ == "__main__":
    main()
