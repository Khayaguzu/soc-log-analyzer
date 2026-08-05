"""Parser and validation logic for normalized authentication logs."""

import csv
import ipaddress
from datetime import datetime
from pathlib import Path

from .models import AuthEvent

REQUIRED_COLUMNS = {
    "timestamp",
    "source_ip",
    "username",
    "outcome",
    "country",
    "event_id",
}
VALID_OUTCOMES = {"SUCCESS", "FAILURE"}


def parse_auth_log(path: Path) -> list[AuthEvent]:
    """Read a CSV log and return validated, time-ordered authentication events.

    Invalid rows are rejected with a clear error instead of being silently ignored,
    because incomplete security telemetry can lead to incorrect conclusions.
    """

    events: list[AuthEvent] = []

    with path.open("r", encoding="utf-8", newline="") as log_file:
        reader = csv.DictReader(log_file)
        columns = set(reader.fieldnames or [])
        missing = REQUIRED_COLUMNS - columns

        if missing:
            raise ValueError(f"Missing required columns: {', '.join(sorted(missing))}")

        for line_number, row in enumerate(reader, start=2):
            try:
                source_ip = row["source_ip"].strip()
                ipaddress.ip_address(source_ip)
                outcome = row["outcome"].strip().upper()

                if outcome not in VALID_OUTCOMES:
                    raise ValueError(f"unsupported outcome '{outcome}'")

                events.append(
                    AuthEvent(
                        timestamp=datetime.fromisoformat(row["timestamp"].strip()),
                        source_ip=source_ip,
                        username=row["username"].strip(),
                        outcome=outcome,
                        country=row["country"].strip().upper(),
                        event_id=row["event_id"].strip(),
                    )
                )
            except (KeyError, ValueError) as error:
                raise ValueError(f"Invalid log row {line_number}: {error}") from error

    return sorted(events, key=lambda event: event.timestamp)
