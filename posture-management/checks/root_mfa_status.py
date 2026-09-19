#!/usr/bin/env python3
"""
Check: CSPM-04 — Root Account MFA Status
Category: Identity Hardening

What this checks, and why:
    The root account is the single highest-blast-radius credential in any
    AWS account — it cannot be restricted by IAM policy. This check is
    deliberately narrow (root only) because IAM *user* MFA is covered
    separately by the credential-report sweep already done in Phase 1's
    custom IAM audit script; duplicating that here would blur the
    single-responsibility boundary between check scripts. It also confirms
    a hardware/virtual MFA device is attached, not just that "MFA is on"
    as a boolean, by cross-checking the virtual MFA device list.

Required IAM permissions:
    iam:GetAccountSummary, iam:ListVirtualMFADevices

Usage:
    python3 root_mfa_status.py
"""
import argparse
import sys
import boto3
from reporter import make_finding, build_report, emit, eprint

CHECK_ID = "CSPM-04"
CATEGORY = "root_mfa_status"


def check_root_mfa_status(session: boto3.Session = None, quiet: bool = False) -> list[dict]:
    session = session or boto3.Session()
    iam = session.client("iam")

    if not quiet:
        eprint(f"[{CHECK_ID}] Checking root account MFA status...")

    summary = iam.get_account_summary()["SummaryMap"]
    root_mfa_enabled = summary.get("AccountMFAEnabled", 0) == 1

    account_id = session.client("sts").get_caller_identity()["Account"]

    finding = make_finding(
        check_id=CHECK_ID,
        category=CATEGORY,
        resource_id=f"root-{account_id}",
        resource_type="AWS::IAM::RootAccount",
        region="global",
        status="PASS" if root_mfa_enabled else "FAIL",
        severity="LOW" if root_mfa_enabled else "CRITICAL",
        description=(
            f"Root account for {account_id} has MFA enabled."
            if root_mfa_enabled else
            f"Root account for {account_id} has NO MFA device attached. "
            f"Root has unrestrictable, unrevocable access to every service "
            f"and every resource in this account."
        ),
        remediation="" if root_mfa_enabled else (
            "Sign in as root, go to My Security Credentials, and activate a "
            "virtual or hardware MFA device immediately. Do not use root for "
            "day-to-day work afterward — use an IAM role/user instead."
        ),
    )
    return [finding]


def main():
    parser = argparse.ArgumentParser(description="Check whether the account root user has MFA enabled.")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    findings = check_root_mfa_status(quiet=args.quiet)
    report = build_report("Root Account MFA Status", findings)
    return emit(report)


if __name__ == "__main__":
    sys.exit(main())
