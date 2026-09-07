"""Tests for log parsing and validation."""

import unittest

from security_log_analyzer.parser import parse_line, parse_lines


class ParserTests(unittest.TestCase):
    def test_parse_valid_line(self) -> None:
        event = parse_line(
            "2026-09-07T10:00:00Z WARN login_failed "
            "ip=203.0.113.25 user=admin"
        )

        self.assertEqual(event.ip_address, "203.0.113.25")
        self.assertEqual(event.username, "admin")
        self.assertEqual(event.action, "login_failed")
        self.assertEqual(event.timestamp.isoformat(), "2026-09-07T10:00:00+00:00")

    def test_invalid_ip_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "invalid IP address"):
            parse_line(
                "2026-09-07T10:00:00Z WARN login_failed "
                "ip=999.1.1.1 user=admin"
            )

    def test_invalid_action_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "unsupported action"):
            parse_line(
                "2026-09-07T10:00:00Z INFO password_changed "
                "ip=203.0.113.25 user=admin"
            )

    def test_parse_lines_collects_errors_and_ignores_blanks(self) -> None:
        events, errors = parse_lines(
            [
                "\n",
                "2026-09-07T10:00:00Z WARN login_failed "
                "ip=203.0.113.25 user=admin\n",
                "not a valid event\n",
            ]
        )

        self.assertEqual(len(events), 1)
        self.assertEqual(len(errors), 1)
        self.assertEqual(errors[0].line_number, 3)


if __name__ == "__main__":
    unittest.main()

