"""Typed data models used by the parser, detection engine, and reporters."""

from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any


@dataclass(frozen=True)
class AuthEvent:
    """Represents one normalized authentication event."""

    timestamp: datetime
    source_ip: str
    username: str
    outcome: str
    country: str
    event_id: str


@dataclass(frozen=True)
class Alert:
    """Represents a detection produced by a correlation rule."""

    rule_id: str
    title: str
    severity: str
    risk_score: int
    source_ip: str
    username: str
    first_seen: datetime
    last_seen: datetime
    event_count: int
    mitre_technique: str
    description: str
    recommendation: str

    def to_dict(self) -> dict[str, Any]:
        """Convert the alert to a JSON-safe dictionary."""

        data = asdict(self)
        data["first_seen"] = self.first_seen.isoformat()
        data["last_seen"] = self.last_seen.isoformat()
        return data
