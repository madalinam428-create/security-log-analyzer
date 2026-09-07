"""Tests for CSV and JSON report generation."""

import csv
import json
import tempfile
import unittest
from pathlib import Path

from security_log_analyzer.analyzer import analyze_events
from security_log_analyzer.parser import parse_lines
from security_log_analyzer.reporting import write_csv, write_json


class ReportingTests(unittest.TestCase):
    def setUp(self) -> None:
        lines = [
            f"2026-09-07T10:0{minute}:00Z WARN login_failed "
            "ip=203.0.113.25 user=admin"
            for minute in range(5)
        ]
        events, self.errors = parse_lines(lines)
        self.result = analyze_events(events)

    def test_csv_report_has_expected_rule(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            output = Path(temporary_directory) / "findings.csv"
            write_csv(self.result.findings, output)

            with output.open(encoding="utf-8", newline="") as csv_file:
                rows = list(csv.DictReader(csv_file))

            self.assertEqual(rows[0]["rule_id"], "BRUTE_FORCE")
            self.assertEqual(rows[0]["ip_address"], "203.0.113.25")

    def test_json_report_contains_statistics(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            output = Path(temporary_directory) / "summary.json"
            write_json(self.result, self.errors, output)

            with output.open(encoding="utf-8") as json_file:
                payload = json.load(json_file)

            self.assertEqual(payload["statistics"]["total_events"], 5)
            self.assertEqual(payload["statistics"]["finding_count"], 1)


if __name__ == "__main__":
    unittest.main()

