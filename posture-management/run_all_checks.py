#!/usr/bin/env python3
"""
run_all_checks.py — DIY CSPM orchestrator (Phase 3, Deliverable 3)

Runs all 8 independent check scripts against the current AWS credentials,
aggregates their findings into one JSON report and a plain-text scorecard,
and writes both to disk under evidence/<timestamp>/.

This does NOT replace running each check script standalone — each remains
independently testable (see checks/*.py, each runnable on its own). This
orchestrator exists for two purposes:
  1. A single command to produce the full-stack posture snapshot used in
     compare_baseline.py and the Deliverable 8 scorecard.
  2. A single command drift_test.py can poll repeatedly after deliberately
     re-introducing a misconfiguration.

Usage:
    python3 run_all_checks.py
    python3 run_all_checks.py --out-dir evidence/post-remediation
    python3 run_all_checks.py --category public_s3_buckets   # run one category only
"""
import argparse
import json
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "checks"))

from public_s3_buckets import check_public_s3_buckets
from open_security_groups import check_open_security_groups
from unencrypted_storage import check_unencrypted_storage
from root_mfa_status import check_root_mfa_status
from logging_enabled import check_logging_enabled
from key_rotation_status import check_key_rotation_status
from public_snapshots import check_public_snapshots
from overprivileged_roles import check_overprivileged_roles

CHECKS = {
    "public_s3_buckets": check_public_s3_buckets,
    "open_security_groups": check_open_security_groups,
    "unencrypted_storage": check_unencrypted_storage,
    "root_mfa_status": check_root_mfa_status,
    "logging_enabled": check_logging_enabled,
    "key_rotation_status": check_key_rotation_status,
    "public_snapshots": check_public_snapshots,
    "overprivileged_roles": check_overprivileged_roles,
}


def run(category: str = None, quiet: bool = False) -> dict:
    selected = {category: CHECKS[category]} if category else CHECKS
    all_findings = []
    per_category = {}

    for name, fn in selected.items():
        if not quiet:
            print(f"=== Running {name} ===", file=sys.stderr)
        findings = fn(quiet=quiet)
        all_findings.extend(findings)
        fail_count = sum(1 for f in findings if f["status"] == "FAIL")
        per_category[name] = {
            "total": len(findings),
            "pass": len(findings) - fail_count,
            "fail": fail_count,
        }

    total_fail = sum(1 for f in all_findings if f["status"] == "FAIL")
    total_pass = sum(1 for f in all_findings if f["status"] == "PASS")

    return {
        "run_timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "total_findings": len(all_findings),
        "total_pass": total_pass,
        "total_fail": total_fail,
        "per_category": per_category,
        "findings": all_findings,
    }


def print_scorecard(report: dict):
    print("\nDIY CSPM Posture Scorecard")
    print("=" * 60)
    print(f"Run time (UTC): {report['run_timestamp_utc']}")
    print(f"{'Category':<28}{'Pass':>8}{'Fail':>8}{'Total':>8}")
    print("-" * 60)
    for cat, counts in report["per_category"].items():
        print(f"{cat:<28}{counts['pass']:>8}{counts['fail']:>8}{counts['total']:>8}")
    print("-" * 60)
    print(f"{'TOTAL':<28}{report['total_pass']:>8}{report['total_fail']:>8}{report['total_findings']:>8}")
    print("=" * 60)


def main():
    parser = argparse.ArgumentParser(description="Run all DIY CSPM checks and produce a combined report.")
    parser.add_argument("--out-dir", default=None,
                         help="directory to write report.json + scorecard.txt into "
                              "(defaults to evidence/<UTC timestamp>/)")
    parser.add_argument("--category", choices=list(CHECKS.keys()), default=None,
                         help="run a single check category instead of all 8")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    report = run(category=args.category, quiet=args.quiet)
    print_scorecard(report)

    out_dir = args.out_dir or os.path.join(
        "evidence", datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    )
    os.makedirs(out_dir, exist_ok=True)
    report_path = os.path.join(out_dir, "report.json")
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"\nFull JSON report written to: {report_path}", file=sys.stderr)

    return 1 if report["total_fail"] > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
