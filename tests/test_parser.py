"""Unit tests for authentication log parsing and validation."""

import tempfile
import unittest
from pathlib import Path

from soc_log_analyzer.parser import parse_auth_log


class ParserTests(unittest.TestCase):
    """Verify accepted and rejected CSV inputs."""

    def test_valid_log_is_parsed(self) -> None:
        content = "timestamp,source_ip,username,outcome,country,event_id\n2026-08-01T10:00:00,192.0.2.1,alice,SUCCESS,ZA,EVT-1\n"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.csv"
            path.write_text(content, encoding="utf-8")
            events = parse_auth_log(path)
        self.assertEqual("alice", events[0].username)

    def test_invalid_ip_is_rejected(self) -> None:
        content = "timestamp,source_ip,username,outcome,country,event_id\n2026-08-01T10:00:00,not-an-ip,alice,SUCCESS,ZA,EVT-1\n"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.csv"
            path.write_text(content, encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "Invalid log row"):
                parse_auth_log(path)


if __name__ == "__main__":
    unittest.main()
