"""Data models used by the parser, analyzer, and reporters."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any


@dataclass(frozen=True, slots=True)
class LogEvent:
    """A validated authentication event."""

    timestamp: datetime
    level: str
    action: str
    ip_address: str
    username: str


@dataclass(frozen=True, slots=True)
class ParseError:
    """A log line that could not be parsed."""

    line_number: int
    raw_line: str
    message: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "line_number": self.line_number,
            "raw_line": self.raw_line,
            "message": self.message,
        }


@dataclass(frozen=True, slots=True)
class Finding:
    """A suspicious pattern detected in the authentication events."""

    rule_id: str
    rule_name: str
    severity: str
    ip_address: str
    start_time: datetime
    end_time: datetime
    event_count: int
    usernames: tuple[str, ...]
    description: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "ip_address": self.ip_address,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat(),
            "event_count": self.event_count,
            "usernames": list(self.usernames),
            "description": self.description,
        }


@dataclass(frozen=True, slots=True)
class AnalysisResult:
    """Summary statistics and all generated findings."""

    total_events: int
    failed_logins: int
    successful_logins: int
    unique_ips: int
    findings: tuple[Finding, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "statistics": {
                "total_events": self.total_events,
                "failed_logins": self.failed_logins,
                "successful_logins": self.successful_logins,
                "unique_ip_addresses": self.unique_ips,
                "finding_count": len(self.findings),
            },
            "findings": [finding.to_dict() for finding in self.findings],
        }

