"""Command-line interface for Security Log Analyzer."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Sequence

from .analyzer import analyze_events
from .parser import parse_file
from .reporting import format_console_report, write_csv, write_json


def _positive_integer(value: str) -> int:
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("value must be at least 1")
    return number


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="security-log-analyzer",
        description="Detect suspicious authentication patterns in an offline log file.",
    )
    parser.add_argument("log_file", type=Path, help="path to the authentication log file")
    parser.add_argument(
        "--failure-threshold",
        type=_positive_integer,
        default=5,
        metavar="N",
        help="failed attempts required for an alert (default: 5)",
    )
    parser.add_argument(
        "--username-threshold",
        type=_positive_integer,
        default=3,
        metavar="N",
        help="distinct usernames required for an alert (default: 3)",
    )
    parser.add_argument(
        "--window-minutes",
        type=_positive_integer,
        default=10,
        metavar="N",
        help="detection window in minutes (default: 10)",
    )
    parser.add_argument("--csv-output", type=Path, help="write findings to a CSV file")
    parser.add_argument("--json-output", type=Path, help="write the full summary to JSON")
    parser.add_argument(
        "--show-parse-errors",
        action="store_true",
        help="print malformed log lines after the analysis",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.log_file.is_file():
        parser.error(f"log file does not exist: {args.log_file}")

    try:
        events, parse_errors = parse_file(args.log_file)
    except OSError as exc:
        parser.error(f"could not read log file: {exc}")

    result = analyze_events(
        events,
        failure_threshold=args.failure_threshold,
        username_threshold=args.username_threshold,
        window_minutes=args.window_minutes,
    )
    print(format_console_report(result, parse_errors))

    if args.csv_output:
        destination = write_csv(result.findings, args.csv_output)
        print(f"\nCSV report:  {destination}")
    if args.json_output:
        destination = write_json(result, parse_errors, args.json_output)
        print(f"JSON report: {destination}")

    if args.show_parse_errors and parse_errors:
        print("\nParse errors:")
        for error in parse_errors:
            print(f"  line {error.line_number}: {error.message} | {error.raw_line}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

