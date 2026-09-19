#!/usr/bin/env python3
"""
compare_baseline.py — Phase 3, Workflow Step 2

"Re-run Prowler post-hardening. Compare directly against your Day 0 baseline
from Phase 1, category by category, with percentage reduction. Show your
math — this is where the required 40%+ improvement figure comes from, and
it must be traceable back to real numbers, not asserted."

This script consumes TWO real Prowler JSON outputs (Prowler's native
`-M json-ocsf` or `-M json` output format) — one from evidence/day0-baseline/
and one from a post-hardening re-run — and computes:
  - total FAIL finding count, before vs after
  - FAIL count broken down by Prowler's `check_metadata.ServiceName`
    (i.e. by category: s3, iam, ec2, rds, cloudtrail, etc.)
  - percentage reduction, overall and per-category
  - a FAIL if overall reduction is below the 40% gate

How to generate the two input files (run these yourself, on your own AWS
account, against the Breach Zone environment):

    # Day 0, BEFORE touching anything (Phase 1):
    prowler aws -M json-ocsf -F day0-baseline -o evidence/day0-baseline/

    # After deliverable 3's hardening work is applied:
    prowler aws -M json-ocsf -F post-hardening -o evidence/post-remediation/

Usage:
    python3 compare_baseline.py \\
        --before evidence/day0-baseline/day0-baseline.ocsf.json \\
        --after  evidence/post-remediation/post-hardening.ocsf.json \\
        --gate-pct 40
"""
import argparse
import json
import sys
from collections import defaultdict


def _load_prowler_findings(path: str) -> list[dict]:
    """Load a Prowler JSON-OCSF output file and return its list of findings.

    Prowler's json-ocsf output is a JSON array of finding objects. Each has
    a `status_code` (or `status`) of PASS/FAIL/MANUAL and metadata identifying
    the service/category it belongs to. This loader is intentionally
    defensive about exact key names since Prowler's schema has changed
    across versions — it tries the common variants.
    """
    with open(path) as f:
        data = json.load(f)
    if isinstance(data, dict) and "findings" in data:
        data = data["findings"]
    return data


def _status_of(finding: dict) -> str:
    for key in ("status", "status_code", "Status"):
        if key in finding:
            val = finding[key]
            return str(val).upper()
    # OCSF nests it sometimes
    return str(finding.get("finding_info", {}).get("status", "UNKNOWN")).upper()


def _category_of(finding: dict) -> str:
    for path in (
        ("check_metadata", "ServiceName"),
        ("ServiceName",),
        ("metadata", "ServiceName"),
        ("resources", 0, "type"),
    ):
        node = finding
        try:
            for key in path:
                node = node[key]
            if node:
                return str(node).lower()
        except (KeyError, IndexError, TypeError):
            continue
    return "uncategorized"


def summarize(findings: list[dict]) -> dict:
    per_category = defaultdict(lambda: {"pass": 0, "fail": 0, "other": 0})
    for f in findings:
        status = _status_of(f)
        cat = _category_of(f)
        if status == "PASS":
            per_category[cat]["pass"] += 1
        elif status == "FAIL":
            per_category[cat]["fail"] += 1
        else:
            per_category[cat]["other"] += 1
    total_fail = sum(c["fail"] for c in per_category.values())
    total_pass = sum(c["pass"] for c in per_category.values())
    return {"per_category": dict(per_category), "total_fail": total_fail, "total_pass": total_pass}


def pct_reduction(before: int, after: int) -> float:
    if before == 0:
        return 0.0
    return round((before - after) / before * 100, 1)


def main():
    parser = argparse.ArgumentParser(description="Compare two Prowler runs and compute % improvement.")
    parser.add_argument("--before", required=True, help="path to Day 0 Prowler JSON-OCSF output")
    parser.add_argument("--after", required=True, help="path to post-hardening Prowler JSON-OCSF output")
    parser.add_argument("--gate-pct", type=float, default=40.0,
                         help="minimum required overall %% reduction in FAIL findings (default 40)")
    args = parser.parse_args()

    before_summary = summarize(_load_prowler_findings(args.before))
    after_summary = summarize(_load_prowler_findings(args.after))

    all_categories = sorted(set(before_summary["per_category"]) | set(after_summary["per_category"]))

    print("Prowler Baseline vs Post-Hardening Comparison")
    print("=" * 78)
    print(f"{'Category':<24}{'Before FAIL':>14}{'After FAIL':>14}{'Reduction':>16}")
    print("-" * 78)
    for cat in all_categories:
        b = before_summary["per_category"].get(cat, {"fail": 0})["fail"]
        a = after_summary["per_category"].get(cat, {"fail": 0})["fail"]
        pct = pct_reduction(b, a)
        print(f"{cat:<24}{b:>14}{a:>14}{pct:>15.1f}%")
    print("-" * 78)

    total_before = before_summary["total_fail"]
    total_after = after_summary["total_fail"]
    total_pct = pct_reduction(total_before, total_after)
    print(f"{'TOTAL':<24}{total_before:>14}{total_after:>14}{total_pct:>15.1f}%")
    print("=" * 78)

    gate_passed = total_pct >= args.gate_pct
    print(f"\nGate: >= {args.gate_pct}% overall FAIL reduction required. "
          f"Actual: {total_pct}%. {'PASSED' if gate_passed else 'FAILED'}.")

    if not gate_passed:
        print("\nDo not report this deliverable as complete — the math does not "
              "clear the required threshold. Continue remediation and re-run.", file=sys.stderr)

    return 0 if gate_passed else 1


if __name__ == "__main__":
    sys.exit(main())
