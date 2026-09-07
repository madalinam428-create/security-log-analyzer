# Security Log Analyzer

An offline Python command-line tool that parses authentication logs, detects suspicious login patterns, and exports investigation-ready CSV and JSON reports.

The project demonstrates practical skills in Python, log analysis, detection engineering, testing, and secure software development. It does not connect to external systems and does not perform network scanning.

## Key features

- Parses structured authentication logs and validates IP addresses and timestamps.
- Detects brute-force attempts from a single IP address.
- Detects possible credential stuffing across multiple usernames.
- Detects a successful login after repeated failures for the same account.
- Continues safely when malformed log lines are found and reports the errors.
- Exports findings to CSV and a complete analysis summary to JSON.
- Uses only the Python standard library at runtime.
- Includes automated tests and a GitHub Actions workflow.

## Detection rules

| Rule ID | Pattern | Default condition |
| --- | --- | --- |
| `BRUTE_FORCE` | Many failed logins from one IP | 5 failures in 10 minutes |
| `CREDENTIAL_STUFFING` | One IP targets several usernames | 3 usernames in 10 minutes |
| `SUCCESS_AFTER_FAILURES` | A login succeeds after repeated failures | 5 failures for the same user in 10 minutes |

Thresholds are configurable from the command line.

## Quick start

Python 3.10 or newer is required.

```bash
git clone https://github.com/madalinam428-create/security-log-analyzer.git
cd security-log-analyzer
python -m security_log_analyzer sample_data/auth.log \
  --csv-output reports/findings.csv \
  --json-output reports/summary.json \
  --show-parse-errors
```

No runtime packages need to be installed.

## Example output

```text
Security Log Analyzer
=====================
Events parsed:       14
Malformed lines:     1
Failed logins:       12
Successful logins:    2
Unique IP addresses:  3
Findings:              3

[HIGH] BRUTE_FORCE - 203.0.113.25
  10 failed logins from one IP within 10 minutes.
[HIGH] CREDENTIAL_STUFFING - 203.0.113.25
  6 distinct usernames targeted from one IP within 10 minutes.
[HIGH] SUCCESS_AFTER_FAILURES - 203.0.113.25
  Successful login for 'admin' after 5 failed attempts within 10 minutes.
```

The sample uses IP ranges reserved for documentation; no real target is involved.

## Log format

Each event must use this format:

```text
2026-09-07T10:00:00Z WARN login_failed ip=203.0.113.25 user=admin
2026-09-07T10:10:00Z INFO login_success ip=203.0.113.25 user=admin
```

Blank lines are ignored. Invalid lines are skipped and included in the parse-error count.

## Command-line options

```text
positional arguments:
  log_file                    Path to the authentication log file

options:
  --failure-threshold N       Failed attempts required for an alert (default: 5)
  --username-threshold N      Distinct usernames required for an alert (default: 3)
  --window-minutes N          Detection window in minutes (default: 10)
  --csv-output PATH           Write findings to a CSV file
  --json-output PATH          Write the full summary to a JSON file
  --show-parse-errors         Print malformed log lines
```

## Run the tests

```bash
python -m unittest discover -s tests -v
```

## Project structure

```text
security-log-analyzer/
├── .github/workflows/tests.yml
├── examples/
│   ├── findings.csv
│   └── summary.json
├── sample_data/auth.log
├── security_log_analyzer/
│   ├── analyzer.py
│   ├── cli.py
│   ├── models.py
│   ├── parser.py
│   └── reporting.py
├── tests/
├── EJOBS_CV_TEXT.md
├── LICENSE
├── README.md
└── pyproject.toml
```

## Responsible use

This tool is intended for defensive analysis of logs that you own or are authorized to inspect. It does not attack accounts, test passwords, or send traffic to third-party systems.

## Author

Madalina Stoean — cybersecurity and Python portfolio project.

