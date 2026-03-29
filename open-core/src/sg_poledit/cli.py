from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .io import format_policy_text, validate_policy_text
from .templates import render_starter_policy_with_comments


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sg-poledit", description="Create and validate SluiceGate policy YAML.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    new_parser = subparsers.add_parser("new", help="Create a starter policy file.")
    new_parser.add_argument("--out", required=True, help="Output YAML path.")

    validate_parser = subparsers.add_parser("validate", help="Validate a policy YAML file.")
    validate_parser.add_argument("path", help="Path to the policy YAML file.")

    format_parser = subparsers.add_parser("format", help="Normalize a policy YAML file in place.")
    format_parser.add_argument("path", help="Path to the policy YAML file.")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "new":
        target = Path(args.out)
        target.write_text(render_starter_policy_with_comments(), encoding="utf-8")
        print(f"Wrote starter policy to {target}")
        return 0

    target = Path(args.path)
    source = target.read_text(encoding="utf-8")

    if args.command == "validate":
        result = validate_policy_text(source)
        print(result.render())
        return 0 if result.is_valid else 1

    if args.command == "format":
        result = validate_policy_text(source)
        if not result.is_valid:
            print(result.render(), file=sys.stderr)
            return 1
        target.write_text(format_policy_text(source), encoding="utf-8")
        print(f"Formatted {target}")
        return 0

    parser.error(f"Unknown command: {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
