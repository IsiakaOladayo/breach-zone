"""
reporter.py — shared finding/report formatting for the DIY CSPM check scripts.

This module deliberately contains NO check logic. It only standardizes the
shape of a "finding" and the shape of a "report" so that:
  - every check script emits the same JSON structure
  - run_all_checks.py can aggregate results from all 8+ checks uniformly
  - compare_baseline.py and drift_test.py can consume any check's output
    without needing to know that check's internals

Each check script remains independently runnable and independently testable —
this file just avoids re-writing the same 15 lines of "build a dict, print
JSON" boilerplate in every one of them.
"""
from __future__ import annotations
import json
import sys
from datetime import datetime, timezone
from typing import Iterable


def make_finding(
    check_id: str,
    category: str,
    resource_id: str,
    resource_type: str,
    region: str,
    status: str,          # "PASS" or "FAIL"
    severity: str,        # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
    description: str,
    remediation: str = "",
) -> dict:
    """Build one standardized finding record."""
    assert status in ("PASS", "FAIL"), "status must be PASS or FAIL"
    assert severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW"), "invalid severity"
    return {
        "check_id": check_id,
        "category": category,
        "resource_id": resource_id,
        "resource_type": resource_type,
        "region": region,
        "status": status,
        "severity": severity,
        "description": description,
        "remediation": remediation,
    }


def build_report(check_name: str, findings: list[dict]) -> dict:
    """Wrap a list of findings with run metadata and a pass/fail summary."""
    fail_count = sum(1 for f in findings if f["status"] == "FAIL")
    pass_count = sum(1 for f in findings if f["status"] == "PASS")
    return {
        "check_name": check_name,
        "run_timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "total_resources_evaluated": len(findings),
        "pass_count": pass_count,
        "fail_count": fail_count,
        "overall_status": "FAIL" if fail_count > 0 else "PASS",
        "findings": findings,
    }


def emit(report: dict, exit_on_fail: bool = True) -> int:
    """Print the report as JSON to stdout and return an exit code.

    Exit code 0 = all resources passed. Exit code 1 = at least one FAIL.
    This lets the script be used directly in CI/CD gating (Phase 4 style)
    as well as invoked programmatically by run_all_checks.py.
    """
    print(json.dumps(report, indent=2, default=str))
    if exit_on_fail and report["overall_status"] == "FAIL":
        return 1
    return 0


def eprint(*args, **kwargs):
    """Print progress/status text to stderr so it never pollutes JSON on stdout."""
    print(*args, file=sys.stderr, **kwargs)
