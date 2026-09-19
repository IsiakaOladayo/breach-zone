#!/usr/bin/env python3
"""
Check: CSPM-08 — Overprivileged Roles
Category: Identity Hardening

What this checks, and why:
    Flags IAM roles whose attached or inline policies contain a statement
    with Effect=Allow AND (Action="*" OR Resource="*") with no meaningful
    Condition block narrowing it. This is a coarse "wildcard smell test,"
    not a full least-privilege analysis (that's what Project 1's
    usage-based right-sizing does with real CloudTrail data) — its job here
    is to surface the *worst* offenders quickly so Deliverable 3's posture
    score reflects that risk category, and to feed the "Rogue Role Hunt"
    narrative in Phase 7.

    AWS service-linked roles (path starting with /aws-service-role/) are
    excluded, since AWS manages their scope and wildcards there are expected
    and cannot be edited by the account owner anyway.

Required IAM permissions:
    iam:ListRoles, iam:ListAttachedRolePolicies, iam:GetPolicy,
    iam:GetPolicyVersion, iam:ListRolePolicies, iam:GetRolePolicy

Usage:
    python3 overprivileged_roles.py
"""
import argparse
import json
import sys
import boto3
from reporter import make_finding, build_report, emit, eprint

CHECK_ID = "CSPM-08"
CATEGORY = "overprivileged_roles"


def _statement_is_wildcard_allow(stmt: dict) -> bool:
    if stmt.get("Effect") != "Allow":
        return False
    if stmt.get("Condition"):
        return False  # a condition may meaningfully narrow this; don't auto-flag
    actions = stmt.get("Action", [])
    resources = stmt.get("Resource", [])
    actions = [actions] if isinstance(actions, str) else actions
    resources = [resources] if isinstance(resources, str) else resources
    return "*" in actions or "*" in resources


def _policy_document_has_wildcard(doc: dict) -> bool:
    stmts = doc.get("Statement", [])
    stmts = [stmts] if isinstance(stmts, dict) else stmts
    return any(_statement_is_wildcard_allow(s) for s in stmts)


def check_overprivileged_roles(session: boto3.Session = None, quiet: bool = False) -> list[dict]:
    session = session or boto3.Session()
    iam = session.client("iam")
    findings = []

    paginator = iam.get_paginator("list_roles")
    roles = [
        r for page in paginator.paginate()
        for r in page["Roles"]
        if not r["Path"].startswith("/aws-service-role/")
    ]
    if not quiet:
        eprint(f"[{CHECK_ID}] Evaluating {len(roles)} IAM role(s) (excluding service-linked)...")

    for role in roles:
        role_name = role["RoleName"]
        wildcard_sources = []

        # Managed policies attached to the role
        attached = iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]
        for pol in attached:
            pol_version = iam.get_policy(PolicyArn=pol["PolicyArn"])["Policy"]["DefaultVersionId"]
            doc = iam.get_policy_version(
                PolicyArn=pol["PolicyArn"], VersionId=pol_version
            )["PolicyVersion"]["Document"]
            if _policy_document_has_wildcard(doc):
                wildcard_sources.append(f"managed policy '{pol['PolicyName']}'")

        # Inline policies on the role
        inline_names = iam.list_role_policies(RoleName=role_name)["PolicyNames"]
        for name in inline_names:
            doc = iam.get_role_policy(RoleName=role_name, PolicyName=name)["PolicyDocument"]
            if _policy_document_has_wildcard(doc):
                wildcard_sources.append(f"inline policy '{name}'")

        is_overprivileged = bool(wildcard_sources)
        findings.append(make_finding(
            check_id=CHECK_ID, category=CATEGORY, resource_id=role_name,
            resource_type="AWS::IAM::Role", region="global",
            status="FAIL" if is_overprivileged else "PASS",
            severity="HIGH" if is_overprivileged else "LOW",
            description=(
                f"Role '{role_name}' has an unconditioned wildcard Allow "
                f"(Action='*' or Resource='*') via: {', '.join(wildcard_sources)}."
                if is_overprivileged else
                f"Role '{role_name}' has no unconditioned wildcard Allow statements."
            ),
            remediation="" if not is_overprivileged else
                        "Replace the wildcard statement with an explicit action/resource list "
                        "derived from real usage data (see Cloud Security Project 1's "
                        "CloudTrail-based right-sizing methodology), or add a Condition block "
                        "that meaningfully narrows scope if the wildcard is intentional.",
        ))
    return findings


def main():
    parser = argparse.ArgumentParser(description="Flag IAM roles with unconditioned wildcard Allow statements.")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    findings = check_overprivileged_roles(quiet=args.quiet)
    report = build_report("Overprivileged Roles", findings)
    return emit(report)


if __name__ == "__main__":
    sys.exit(main())
