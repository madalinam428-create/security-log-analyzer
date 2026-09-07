"""Tests for the suspicious-login detection rules."""

import unittest

from security_log_analyzer.analyzer import analyze_events
from security_log_analyzer.parser import parse_lines


def make_events(lines: list[str]):
    events, errors = parse_lines(lines)
    if errors:
        raise AssertionError(f"Unexpected parse errors: {errors}")
    return events


class AnalyzerTests(unittest.TestCase):
    def test_detects_brute_force_and_credential_stuffing(self) -> None:
        lines = [
            f"2026-09-07T10:0{minute}:00Z WARN login_failed "
            f"ip=203.0.113.25 user={username}"
            for minute, username in enumerate(
                ["admin", "admin", "root", "admin", "guest", "admin"]
            )
        ]

        result = analyze_events(make_events(lines))
        rule_ids = {finding.rule_id for finding in result.findings}

        self.assertIn("BRUTE_FORCE", rule_ids)
        self.assertIn("CREDENTIAL_STUFFING", rule_ids)

    def test_detects_success_after_repeated_failures(self) -> None:
        lines = [
            f"2026-09-07T10:0{minute}:00Z WARN login_failed "
            "ip=203.0.113.25 user=admin"
            for minute in range(5)
        ]
        lines.append(
            "2026-09-07T10:05:00Z INFO login_success "
            "ip=203.0.113.25 user=admin"
        )

        result = analyze_events(make_events(lines))
        success_findings = [
            finding
            for finding in result.findings
            if finding.rule_id == "SUCCESS_AFTER_FAILURES"
        ]

        self.assertEqual(len(success_findings), 1)
        self.assertEqual(success_findings[0].severity, "HIGH")

    def test_events_outside_window_do_not_trigger(self) -> None:
        lines = [
            f"2026-09-07T10:{minute * 11:02d}:00Z WARN login_failed "
            "ip=203.0.113.25 user=admin"
            for minute in range(5)
        ]

        result = analyze_events(make_events(lines), window_minutes=10)

        self.assertEqual(result.findings, ())

    def test_rejects_invalid_thresholds(self) -> None:
        with self.assertRaisesRegex(ValueError, "failure_threshold"):
            analyze_events([], failure_threshold=0)


if __name__ == "__main__":
    unittest.main()

