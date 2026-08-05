"""Console, JSON, and CSV alert reporting."""

import csv
import json
from pathlib import Path

from .models import Alert


def print_summary(alerts: list[Alert]) -> None:
    """Print a compact analyst-friendly alert table."""

    if not alerts:
        print("No suspicious activity detected.")
        return

    print(f"Detected {len(alerts)} alert(s)\n")
    print(f"{'SEVERITY':<10} {'RISK':<6} {'RULE':<9} {'USER':<16} {'SOURCE IP':<16} TITLE")
    print("-" * 95)
    for alert in alerts:
        print(
            f"{alert.severity:<10} {alert.risk_score:<6} {alert.rule_id:<9} "
            f"{alert.username:<16} {alert.source_ip:<16} {alert.title}"
        )


def write_json(alerts: list[Alert], path: Path) -> None:
    """Write alerts as structured JSON for SIEM-style integration."""

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps([alert.to_dict() for alert in alerts], indent=2), encoding="utf-8")


def write_csv(alerts: list[Alert], path: Path) -> None:
    """Write alerts to CSV for spreadsheet analysis."""

    path.parent.mkdir(parents=True, exist_ok=True)
    rows = [alert.to_dict() for alert in alerts]
    if not rows:
        path.write_text("", encoding="utf-8")
        return

    with path.open("w", encoding="utf-8", newline="") as report_file:
        writer = csv.DictWriter(report_file, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)
