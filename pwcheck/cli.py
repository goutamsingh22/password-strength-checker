"""Command line interface for the password strength checker."""

from __future__ import annotations

import argparse
import getpass
import json
import sys
from typing import Sequence

from . import __version__
from .checker import CHECKS, PasswordReport, check_password

__all__ = ["build_parser", "main"]

BANNER = r"""
 ____            ____ _               _
|  _ \ __      __/ ___| |__   ___  ___| | __
| |_) \ \ /\ / / |   | '_ \ / _ \/ __| |/ /
|  __/ \ V  V /| |___| | | |  __/ (__|   <
|_|     \_/\_/  \____|_| |_|\___|\___|_|\_\
"""


def _read_password() -> str | None:
    """Read a password from the terminal or piped standard input."""
    if sys.stdin.isatty():
        try:
            return getpass.getpass("Password: ")
        except (EOFError, KeyboardInterrupt):
            return None
    line = sys.stdin.readline()
    return line.rstrip("\r\n") if line else None


def _render(report: PasswordReport) -> None:
    print(BANNER.strip("\n"))
    print()
    print(f"Strength  : {report.label} ({report.score}/100)")
    print(f"Length    : {report.length} characters")
    print(f"Entropy   : {report.entropy_bits:.1f} bits (upper bound)")
    print()
    print("Checks:")
    for key, label in CHECKS:
        mark = "x" if report.checks.get(key) else " "
        print(f"  [{mark}] {label}")

    if report.warnings:
        print()
        print("Warnings:")
        for warning in report.warnings:
            print(f"  - {warning}")

    print()
    print("Suggestions:")
    for suggestion in report.suggestions:
        print(f"  - {suggestion}")


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser for the ``pwcheck`` command."""
    parser = argparse.ArgumentParser(
        prog="pwcheck",
        description="Evaluate password strength and suggest improvements.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            '  pwcheck "Tr0ub4dor&3"\n'
            '  pwcheck --json "correct horse battery staple"\n'
            "  echo 'Summer2024!' | pwcheck\n"
            "  pwcheck --min-score 60 \"$(passgen generate)\"\n"
        ),
    )
    parser.add_argument(
        "password",
        nargs="?",
        help="password to check (prompted for or read from stdin when omitted)",
    )
    parser.add_argument("-j", "--json", action="store_true", help="print the report as JSON")
    parser.add_argument("-q", "--quiet", action="store_true", help="print only the rating")
    parser.add_argument(
        "--min-score",
        type=int,
        default=None,
        metavar="N",
        help="exit with status 1 when the score is below N (0-100)",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point for the ``pwcheck`` command.

    Args:
        argv: Command line arguments. Defaults to ``sys.argv[1:]``.

    Returns:
        The process exit code.
    """
    parser = build_parser()
    args = parser.parse_args(list(sys.argv[1:] if argv is None else argv))

    if args.min_score is not None and not 0 <= args.min_score <= 100:
        parser.error("--min-score must be between 0 and 100")

    password = args.password
    if password is None:
        password = _read_password()
    if password is None:
        print("error: no password supplied", file=sys.stderr)
        return 2

    report = check_password(password)

    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    elif args.quiet:
        print(f"{report.label} ({report.score}/100)")
    else:
        _render(report)

    if args.min_score is not None and report.score < args.min_score:
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
