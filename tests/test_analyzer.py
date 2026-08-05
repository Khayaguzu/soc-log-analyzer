"""Unit tests for SOC detection rules."""

import unittest
from datetime import datetime, timedelta

from soc_log_analyzer.analyzer import analyze_events
from soc_log_analyzer.models import AuthEvent


class AnalyzerTests(unittest.TestCase):
    """Verify that malicious patterns generate the expected alerts."""

    def event(self, minute: int, ip: str, user: str, outcome: str, country: str = "ZA") -> AuthEvent:
        """Create a deterministic authentication event for a test scenario."""

        return AuthEvent(datetime(2026, 8, 1, 10, 0) + timedelta(minutes=minute), ip, user, outcome, country, str(minute))

    def test_brute_force_detection(self) -> None:
        events = [self.event(minute, "203.0.113.10", "alice", "FAILURE") for minute in range(5)]
        rule_ids = {alert.rule_id for alert in analyze_events(events)}
        self.assertIn("SOC-001", rule_ids)

    def test_password_spraying_detection(self) -> None:
        events = [self.event(index, "198.51.100.25", f"user{index}", "FAILURE") for index in range(5)]
        rule_ids = {alert.rule_id for alert in analyze_events(events)}
        self.assertIn("SOC-002", rule_ids)

    def test_success_after_failures_detection(self) -> None:
        events = [self.event(index, "192.0.2.50", "bob", "FAILURE") for index in range(3)]
        events.append(self.event(4, "192.0.2.50", "bob", "SUCCESS"))
        alerts = analyze_events(events)
        compromise = next(alert for alert in alerts if alert.rule_id == "SOC-003")
        self.assertEqual("CRITICAL", compromise.severity)

    def test_impossible_travel_detection(self) -> None:
        events = [
            self.event(0, "192.0.2.1", "carol", "SUCCESS", "ZA"),
            self.event(30, "198.51.100.1", "carol", "SUCCESS", "GB"),
        ]
        rule_ids = {alert.rule_id for alert in analyze_events(events)}
        self.assertIn("SOC-004", rule_ids)

    def test_normal_activity_has_no_alerts(self) -> None:
        events = [
            self.event(0, "192.0.2.10", "dave", "SUCCESS"),
            self.event(20, "192.0.2.11", "erin", "FAILURE"),
        ]
        self.assertEqual([], analyze_events(events))


if __name__ == "__main__":
    unittest.main()
