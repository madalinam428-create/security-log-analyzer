"""Parse and validate structured authentication log lines."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from ipaddress import ip_address
from pathlib import Path
from typing import Iterable

from .models import LogEvent, ParseError


LOG_PATTERN = re.compile(
    r"^(?P<timestamp>\S+)\s+"
    r"(?P<level>[A-Z]+)\s+"
    r"(?P<action>[a-z_]+)\s+"
    r"ip=(?P<ip>\S+)\s+"
    r"user=(?P<username>\S+)\s*$"
)

ALLOWED_LEVELS = {"DEBUG", "INFO", "WARN", "ERROR"}
ALLOWED_ACTIONS = {"login_failed", "login_success"}


def _parse_timestamp(value: str) -> datetime:
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        timestamp = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ValueError(f"invalid timestamp: {value}") from exc

    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=UTC)
    return timestamp.astimezone(UTC)


def parse_line(line: str) -> LogEvent:
    """Parse one log line and raise ``ValueError`` when it is invalid."""

    match = LOG_PATTERN.fullmatch(line.strip())
    if not match:
        raise ValueError("line does not match the expected log format")

    level = match.group("level")
    action = match.group("action")
    raw_ip = match.group("ip")

    if level not in ALLOWED_LEVELS:
        raise ValueError(f"unsupported log level: {level}")
    if action not in ALLOWED_ACTIONS:
        raise ValueError(f"unsupported action: {action}")

    try:
        validated_ip = str(ip_address(raw_ip))
    except ValueError as exc:
        raise ValueError(f"invalid IP address: {raw_ip}") from exc

    return LogEvent(
        timestamp=_parse_timestamp(match.group("timestamp")),
        level=level,
        action=action,
        ip_address=validated_ip,
        username=match.group("username"),
    )


def parse_lines(lines: Iterable[str]) -> tuple[list[LogEvent], list[ParseError]]:
    """Parse multiple lines while collecting, rather than hiding, bad records."""

    events: list[LogEvent] = []
    errors: list[ParseError] = []

    for line_number, raw_line in enumerate(lines, start=1):
        stripped = raw_line.strip()
        if not stripped:
            continue
        try:
            events.append(parse_line(stripped))
        except ValueError as exc:
            errors.append(
                ParseError(
                    line_number=line_number,
                    raw_line=stripped,
                    message=str(exc),
                )
            )

    events.sort(key=lambda event: event.timestamp)
    return events, errors


def parse_file(path: str | Path) -> tuple[list[LogEvent], list[ParseError]]:
    """Read and parse a UTF-8 authentication log file."""

    log_path = Path(path)
    with log_path.open("r", encoding="utf-8") as log_file:
        return parse_lines(log_file)

