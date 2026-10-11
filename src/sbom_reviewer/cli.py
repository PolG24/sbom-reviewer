"""Command-line entry point for the SBOM reviewer."""

import argparse
from pathlib import Path

from sbom_reviewer.decisions import DecisionError
from sbom_reviewer.models import Decision, ReviewResult
from sbom_reviewer.policy import load_policy
from sbom_reviewer.report import render_report
from sbom_reviewer.review import review_components
from sbom_reviewer.sbom import load_sbom
from sbom_reviewer.storage import StorageError, load_review, record_decision, save_review


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
    review.add_argument("--fetch-model-cards", action="store_true",
                        help="Fetch public Hugging Face Markdown model cards for evidence review (opt-in network access).")
    review.add_argument("--save-review", type=Path, help="Save the complete machine snapshot to a new SQLite file.")
    decide = commands.add_parser("decide", help="Confirm a machine recommendation or record a reviewer override.")
    decide.add_argument("database", type=Path, help="Path to an existing saved review.")
    decide.add_argument("--component", required=True, help="Exact component ID (original JSON pointer).")
    action = decide.add_mutually_exclusive_group(required=True)
    action.add_argument("--confirm", action="store_true", help="Confirm the original machine recommendation.")
    action.add_argument("--override", choices=[item.value for item in Decision], help="Record a different human outcome.")
    decide.add_argument("--reviewer", required=True, help="Nonblank reviewer name.")
    decide.add_argument("--reason", required=True, help="Nonblank rationale for this action.")
    show = commands.add_parser("show", help="Inspect a saved review, current human decisions, and audit history.")
    show.add_argument("database", type=Path, help="Path to an existing saved review.")
    export = commands.add_parser("export", help="Export a standalone HTML report from an existing saved review.")
    export.add_argument("database", type=Path, help="Path to an existing saved review.")
    export.add_argument("--output", type=Path, required=True, help="New UTF-8 HTML output path (must not exist).")
    return parser


def _review(args: argparse.Namespace, parser: argparse.ArgumentParser) -> ReviewResult:
    try:
        policy = load_policy(args.policy)
    except (OSError, ValueError) as exc:
        parser.error(f"Cannot load policy '{args.policy}': {exc}")
    try:
        components = load_sbom(args.sbom)
    except (OSError, ValueError) as exc:
        parser.error(f"Cannot review SBOM '{args.sbom}': {exc}")
    result = review_components(components, policy, fetch_model_cards=args.fetch_model_cards)
    if args.save_review is not None:
        save_review(args.save_review, result)
    return result


def main() -> None:
    """Emit command JSON only after success, or an actionable error (exit 2)."""
    parser = build_parser()
    args = parser.parse_args()
    try:
        if args.command == "review":
            result = _review(args, parser)
        elif args.command == "decide":
            result = record_decision(args.database, args.component, confirm=args.confirm,
                                     override=args.override, reviewer=args.reviewer, reason=args.reason)
        elif args.command == "show":
            result = load_review(args.database)
        else:
            document = render_report(load_review(args.database))
            _write_report(args.output, document)
            return
    except (StorageError, DecisionError) as exc:
        parser.error(str(exc))
    print(result.model_dump_json(indent=2))


def _write_report(path: Path, document: str) -> None:
    try:
        with path.open("x", encoding="utf-8") as stream:
            stream.write(document)
    except OSError as exc:
        raise StorageError(f"Cannot write report '{path}': {exc}") from exc


if __name__ == "__main__":
    main()
