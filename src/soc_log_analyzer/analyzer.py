"""Correlation rules for suspicious authentication behaviour."""

from collections import defaultdict
from datetime import timedelta

from .models import Alert, AuthEvent


def analyze_events(events: list[AuthEvent]) -> list[Alert]:
    """Run every detection rule and return alerts ordered by risk."""

    alerts = []
    alerts.extend(_detect_brute_force(events))
    alerts.extend(_detect_password_spraying(events))
    alerts.extend(_detect_success_after_failures(events))
    alerts.extend(_detect_impossible_travel(events))
    return sorted(alerts, key=lambda alert: (-alert.risk_score, alert.first_seen))


def _detect_brute_force(events: list[AuthEvent]) -> list[Alert]:
    """Detect at least five failures against one account from one IP in 10 minutes."""

    groups: dict[tuple[str, str], list[AuthEvent]] = defaultdict(list)
    for event in events:
        if event.outcome == "FAILURE":
            groups[(event.source_ip, event.username)].append(event)

    alerts = []
    for (source_ip, username), failures in groups.items():
        window = _largest_window(failures, timedelta(minutes=10))
        if len(window) >= 5:
            alerts.append(
                Alert(
                    "SOC-001", "Possible brute-force attack", "HIGH", 80,
                    source_ip, username, window[0].timestamp, window[-1].timestamp,
                    len(window), "T1110.001 Password Guessing",
                    "Repeated authentication failures targeted one account.",
                    "Temporarily block the source, review the account, and enforce MFA.",
                )
            )
    return alerts


def _detect_password_spraying(events: list[AuthEvent]) -> list[Alert]:
    """Detect one IP failing against at least five accounts in 15 minutes."""

    failures_by_ip: dict[str, list[AuthEvent]] = defaultdict(list)
    for event in events:
        if event.outcome == "FAILURE":
            failures_by_ip[event.source_ip].append(event)

    alerts = []
    for source_ip, failures in failures_by_ip.items():
        window = _largest_window(failures, timedelta(minutes=15))
        usernames = {event.username for event in window}
        if len(usernames) >= 5:
            alerts.append(
                Alert(
                    "SOC-002", "Possible password-spraying attack", "HIGH", 85,
                    source_ip, "multiple", window[0].timestamp, window[-1].timestamp,
                    len(window), "T1110.003 Password Spraying",
                    f"One source failed authentication against {len(usernames)} accounts.",
                    "Block the source, identify targeted users, reset exposed credentials, and enforce MFA.",
                )
            )
    return alerts


def _detect_success_after_failures(events: list[AuthEvent]) -> list[Alert]:
    """Detect a successful login shortly after repeated failures from the same IP."""

    alerts = []
    for success in (event for event in events if event.outcome == "SUCCESS"):
        start = success.timestamp - timedelta(minutes=15)
        failures = [
            event for event in events
            if event.outcome == "FAILURE"
            and event.source_ip == success.source_ip
            and event.username == success.username
            and start <= event.timestamp < success.timestamp
        ]
        if len(failures) >= 3:
            alerts.append(
                Alert(
                    "SOC-003", "Successful login after repeated failures", "CRITICAL", 95,
                    success.source_ip, success.username, failures[0].timestamp,
                    success.timestamp, len(failures) + 1, "T1078 Valid Accounts",
                    "A login succeeded after repeated failures, which may indicate account compromise.",
                    "Disable active sessions, verify the user, reset credentials, and investigate the endpoint.",
                )
            )
    return alerts


def _detect_impossible_travel(events: list[AuthEvent]) -> list[Alert]:
    """Flag successful logins from different countries within 60 minutes."""

    successes_by_user: dict[str, list[AuthEvent]] = defaultdict(list)
    for event in events:
        if event.outcome == "SUCCESS":
            successes_by_user[event.username].append(event)

    alerts = []
    for username, successes in successes_by_user.items():
        for previous, current in zip(successes, successes[1:]):
            elapsed = current.timestamp - previous.timestamp
            if previous.country != current.country and elapsed <= timedelta(minutes=60):
                alerts.append(
                    Alert(
                        "SOC-004", "Potential impossible travel", "HIGH", 88,
                        current.source_ip, username, previous.timestamp, current.timestamp,
                        2, "T1078 Valid Accounts",
                        f"Successful logins occurred in {previous.country} and {current.country} within {int(elapsed.total_seconds() // 60)} minutes.",
                        "Verify both logins, revoke suspicious sessions, and require MFA reauthentication.",
                    )
                )
    return alerts


def _largest_window(events: list[AuthEvent], duration: timedelta) -> list[AuthEvent]:
    """Return the largest chronological event window within the specified duration."""

    best: list[AuthEvent] = []
    left = 0
    for right, event in enumerate(events):
        while event.timestamp - events[left].timestamp > duration:
            left += 1
        candidate = events[left:right + 1]
        if len(candidate) > len(best):
            best = candidate
    return best
