"""Console, CSV, and JSON reports for analysis results."""

from __future__ import annotations

import csv
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence

from .models import AnalysisResult, Finding, ParseError


CSV_FIELDS = [
    "severity",
    "rule_id",
    "rule_name",
    "ip_address",
    "start_time",
    "end_time",
    "event_count",
    "usernames",
    "description",
]


def format_console_report(
    result: AnalysisResult, parse_errors: Sequence[ParseError]
) -> str:
    """Build a readable terminal summary."""

    lines = [
        "Security Log Analyzer",
        "=====================",
        f"Events parsed:       {result.total_events:>3}",
        f"Malformed lines:     {len(parse_errors):>3}",
        f"Failed logins:       {result.failed_logins:>3}",
        f"Successful logins:   {result.successful_logins:>3}",
        f"Unique IP addresses: {result.unique_ips:>3}",
        f"Findings:            {len(result.findings):>3}",
    ]

    if result.findings:
        lines.append("")
        for finding in result.findings:
            lines.extend(
                [
                    f"[{finding.severity}] {finding.rule_id} - {finding.ip_address}",
                    f"  {finding.description}",
                ]
            )
    else:
        lines.extend(["", "No suspicious patterns matched the configured thresholds."])

    return "\n".join(lines)


def write_csv(findings: Sequence[Finding], output_path: str | Path) -> Path:
    """Export findings to CSV and return the created path."""

    destination = Path(output_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("w", encoding="utf-8", newline="") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=CSV_FIELDS)
        writer.writeheader()
        for finding in findings:
            row = finding.to_dict()
            row["usernames"] = ",".join(finding.usernames)
            writer.writerow({field: row[field] for field in CSV_FIELDS})
    return destination


def write_json(
    result: AnalysisResult,
    parse_errors: Sequence[ParseError],
    output_path: str | Path,
) -> Path:
    """Export statistics, findings, and parse errors to JSON."""

    destination = Path(output_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        **result.to_dict(),
        "parse_errors": [error.to_dict() for error in parse_errors],
    }
    with destination.open("w", encoding="utf-8") as json_file:
        json.dump(payload, json_file, indent=2, ensure_ascii=False)
        json_file.write("\n")
    return destination

