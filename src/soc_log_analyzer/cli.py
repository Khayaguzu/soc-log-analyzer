"""Command-line interface for the SOC Log Analyzer."""

import argparse
from pathlib import Path

from .analyzer import analyze_events
from .parser import parse_auth_log
from .reporting import print_summary, write_csv, write_json


def build_parser() -> argparse.ArgumentParser:
    """Create and configure the command-line argument parser."""

    parser = argparse.ArgumentParser(description="Detect suspicious authentication activity in CSV logs.")
    parser.add_argument("log_file", type=Path, help="Path to a normalized authentication CSV file.")
    parser.add_argument("--json", type=Path, dest="json_path", help="Optional JSON report path.")
    parser.add_argument("--csv", type=Path, dest="csv_path", help="Optional CSV report path.")
    return parser


def main() -> int:
    """Parse arguments, analyze events, and generate requested reports."""

    args = build_parser().parse_args()
    try:
        alerts = analyze_events(parse_auth_log(args.log_file))
    except (OSError, ValueError) as error:
        print(f"Analysis failed: {error}")
        return 1

    print_summary(alerts)
    if args.json_path:
        write_json(alerts, args.json_path)
    if args.csv_path:
        write_csv(alerts, args.csv_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
