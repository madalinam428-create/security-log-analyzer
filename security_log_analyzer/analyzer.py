"""Detection rules for suspicious authentication activity."""

from __future__ import annotations

from collections import defaultdict
from datetime import timedelta
from typing import Callable, Sequence

from .models import AnalysisResult, Finding, LogEvent


SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def _severity(observed: int, threshold: int) -> str:
    if observed >= threshold * 3:
        return "CRITICAL"
    if observed >= threshold * 2:
        return "HIGH"
    return "MEDIUM"


def _largest_window(
    events: Sequence[LogEvent],
    window: timedelta,
    score: Callable[[Sequence[LogEvent]], int] = len,
) -> list[LogEvent]:
    """Return the time window with the highest score."""

    best: list[LogEvent] = []
    best_score = 0
    left = 0

    for right, event in enumerate(events):
        while event.timestamp - events[left].timestamp > window:
            left += 1
        candidate = list(events[left : right + 1])
        candidate_score = score(candidate)
        if candidate_score > best_score or (
            candidate_score == best_score and len(candidate) > len(best)
        ):
            best = candidate
            best_score = candidate_score

    return best


def _detect_ip_patterns(
    failed_by_ip: dict[str, list[LogEvent]],
    failure_threshold: int,
    username_threshold: int,
    window: timedelta,
    window_minutes: int,
) -> list[Finding]:
    findings: list[Finding] = []

    for source_ip, failures in failed_by_ip.items():
        failures.sort(key=lambda event: event.timestamp)

        brute_window = _largest_window(failures, window)
        if len(brute_window) >= failure_threshold:
            usernames = tuple(sorted({event.username for event in brute_window}))
            findings.append(
                Finding(
                    rule_id="BRUTE_FORCE",
                    rule_name="Possible brute-force attack",
                    severity=_severity(len(brute_window), failure_threshold),
                    ip_address=source_ip,
                    start_time=brute_window[0].timestamp,
                    end_time=brute_window[-1].timestamp,
                    event_count=len(brute_window),
                    usernames=usernames,
                    description=(
                        f"{len(brute_window)} failed logins from one IP within "
                        f"{window_minutes} minutes."
                    ),
                )
            )

        stuffing_window = _largest_window(
            failures,
            window,
            score=lambda items: len({item.username for item in items}),
        )
        targeted_users = tuple(sorted({event.username for event in stuffing_window}))
        if len(targeted_users) >= username_threshold:
            findings.append(
                Finding(
                    rule_id="CREDENTIAL_STUFFING",
                    rule_name="Possible credential-stuffing attack",
                    severity=_severity(len(targeted_users), username_threshold),
                    ip_address=source_ip,
                    start_time=stuffing_window[0].timestamp,
                    end_time=stuffing_window[-1].timestamp,
                    event_count=len(stuffing_window),
                    usernames=targeted_users,
                    description=(
                        f"{len(targeted_users)} distinct usernames targeted from one IP "
                        f"within {window_minutes} minutes."
                    ),
                )
            )

    return findings


def _detect_success_after_failures(
    events: Sequence[LogEvent],
    failure_threshold: int,
    window: timedelta,
    window_minutes: int,
) -> list[Finding]:
    failures_by_identity: dict[tuple[str, str], list[LogEvent]] = defaultdict(list)
    successes: list[LogEvent] = []

    for event in events:
        identity = (event.ip_address, event.username)
        if event.action == "login_failed":
            failures_by_identity[identity].append(event)
        elif event.action == "login_success":
            successes.append(event)

    findings: list[Finding] = []
    alerted_identities: set[tuple[str, str]] = set()

    for success in sorted(successes, key=lambda event: event.timestamp):
        identity = (success.ip_address, success.username)
        if identity in alerted_identities:
            continue

        recent_failures = [
            failure
            for failure in failures_by_identity.get(identity, [])
            if timedelta(0) <= success.timestamp - failure.timestamp <= window
        ]
        if len(recent_failures) < failure_threshold:
            continue

        findings.append(
            Finding(
                rule_id="SUCCESS_AFTER_FAILURES",
                rule_name="Successful login after repeated failures",
                severity="HIGH",
                ip_address=success.ip_address,
                start_time=recent_failures[0].timestamp,
                end_time=success.timestamp,
                event_count=len(recent_failures) + 1,
                usernames=(success.username,),
                description=(
                    f"Successful login for '{success.username}' after "
                    f"{len(recent_failures)} failed attempts within "
                    f"{window_minutes} minutes."
                ),
            )
        )
        alerted_identities.add(identity)

    return findings


def analyze_events(
    events: Sequence[LogEvent],
    failure_threshold: int = 5,
    username_threshold: int = 3,
    window_minutes: int = 10,
) -> AnalysisResult:
    """Run all detection rules and return a complete analysis summary."""

    if failure_threshold < 1:
        raise ValueError("failure_threshold must be at least 1")
    if username_threshold < 1:
        raise ValueError("username_threshold must be at least 1")
    if window_minutes < 1:
        raise ValueError("window_minutes must be at least 1")

    ordered_events = sorted(events, key=lambda event: event.timestamp)
    failed_events = [event for event in ordered_events if event.action == "login_failed"]
    successful_events = [
        event for event in ordered_events if event.action == "login_success"
    ]
    failed_by_ip: dict[str, list[LogEvent]] = defaultdict(list)
    for event in failed_events:
        failed_by_ip[event.ip_address].append(event)

    window = timedelta(minutes=window_minutes)
    findings = _detect_ip_patterns(
        failed_by_ip=failed_by_ip,
        failure_threshold=failure_threshold,
        username_threshold=username_threshold,
        window=window,
        window_minutes=window_minutes,
    )
    findings.extend(
        _detect_success_after_failures(
            events=ordered_events,
            failure_threshold=failure_threshold,
            window=window,
            window_minutes=window_minutes,
        )
    )
    findings.sort(
        key=lambda finding: (
            SEVERITY_ORDER[finding.severity],
            finding.ip_address,
            finding.rule_id,
        )
    )

    return AnalysisResult(
        total_events=len(ordered_events),
        failed_logins=len(failed_events),
        successful_logins=len(successful_events),
        unique_ips=len({event.ip_address for event in ordered_events}),
        findings=tuple(findings),
    )

