#!/usr/bin/env python3
"""
Check: CSPM-06 — Access Key Rotation Status
Category: Identity Hardening

What this checks, and why:
    Long-lived IAM access keys are a standing liability: the longer a key
    exists, the more places it may have leaked into (CI logs, laptops,
    .bash_history, screenshots). This check flags any *active* access key
    older than a configurable threshold (default 90 days, matching the
    Phase 1 custom IAM audit script's threshold so before/after comparisons
    are apples-to-apples), and separately flags any user carrying two active
    keys at once, which usually means an old key was never deleted after
    rotation, only left active "just in case."

Required IAM permissions:
    iam:ListUsers, iam:ListAccessKeys, iam:GetAccessKeyLastUsed

Usage:
    python3 key_rotation_status.py
    python3 key_rotation_status.py --max-age-days 90
"""
import argparse
import sys
from datetime import datetime, timezone
import boto3
from reporter import make_finding, build_report, emit, eprint

CHECK_ID = "CSPM-06"
CATEGORY = "key_rotation_status"
DEFAULT_MAX_AGE_DAYS = 90


def check_key_rotation_status(session: boto3.Session = None, max_age_days: int = DEFAULT_MAX_AGE_DAYS,
                               quiet: bool = False) -> list[dict]:
    session = session or boto3.Session()
    iam = session.client("iam")
    findings = []

    paginator = iam.get_paginator("list_users")
    users = [u for page in paginator.paginate() for u in page["Users"]]
    if not quiet:
        eprint(f"[{CHECK_ID}] Checking access keys for {len(users)} IAM user(s)...")

    now = datetime.now(timezone.utc)

    for user in users:
        username = user["UserName"]
        keys = iam.list_access_keys(UserName=username)["AccessKeyMetadata"]
        active_keys = [k for k in keys if k["Status"] == "Active"]

        if len(active_keys) >= 2:
            findings.append(make_finding(
                check_id=CHECK_ID, category=CATEGORY, resource_id=username,
                resource_type="AWS::IAM::User", region="global", status="FAIL",
                severity="MEDIUM",
                description=f"User '{username}' has {len(active_keys)} active access keys "
                            f"simultaneously, suggesting an old key was never deactivated "
                            f"after rotation.",
                remediation="Confirm the older key is unused (check GetAccessKeyLastUsed), "
                            "then deactivate and delete it.",
            ))

        for k in keys:
            if k["Status"] != "Active":
                continue
            age_days = (now - k["CreateDate"]).days
            last_used_resp = iam.get_access_key_last_used(AccessKeyId=k["AccessKeyId"])
            last_used = last_used_resp.get("AccessKeyLastUsed", {}).get("LastUsedDate")
            too_old = age_days > max_age_days

            findings.append(make_finding(
                check_id=CHECK_ID, category=CATEGORY, resource_id=k["AccessKeyId"],
                resource_type="AWS::IAM::AccessKey", region="global",
                status="FAIL" if too_old else "PASS",
                severity="HIGH" if too_old else "LOW",
                description=(
                    f"Access key {k['AccessKeyId']} (user '{username}') is {age_days} days "
                    f"old (threshold {max_age_days}), last used "
                    f"{last_used.isoformat() if last_used else 'never'}."
                ),
                remediation="" if not too_old else
                            "Create a new access key, update the application/CI secret store, "
                            "confirm the new key works, then deactivate and delete the old one. "
                            "If this key is used by a deployment pipeline, prefer replacing it "
                            "entirely with OIDC-based role assumption instead of rotating it "
                            "(see Cloud Security Project 1 for the federation pattern).",
            ))
    return findings


def main():
    parser = argparse.ArgumentParser(description="Check IAM access key age and duplicate active keys.")
    parser.add_argument("--max-age-days", type=int, default=DEFAULT_MAX_AGE_DAYS)
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    findings = check_key_rotation_status(max_age_days=args.max_age_days, quiet=args.quiet)
    report = build_report("Access Key Rotation Status", findings)
    return emit(report)


if __name__ == "__main__":
    sys.exit(main())
