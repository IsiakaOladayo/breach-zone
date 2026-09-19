#!/usr/bin/env python3
"""
Check: CSPM-01 — Public S3 Buckets
Category: Storage Exposure

What this checks, and why:
    An S3 bucket is "effectively public" if either (a) its bucket ACL grants
    access to the "AllUsers" or "AuthenticatedUsers" S3 predefined groups, or
    (b) its bucket policy allows a public principal ("*") AND the bucket's
    Public Access Block (PAB) settings don't override that policy. Checking
    only the ACL or only the policy misses real exposure, so this check
    inspects both, plus the PAB configuration itself, which is what AWS
    Config's own managed rule (s3-bucket-public-read-prohibited) does under
    the hood.

Required IAM permissions:
    s3:ListAllMyBuckets, s3:GetBucketAcl, s3:GetBucketPolicyStatus,
    s3:GetPublicAccessBlock, s3:GetBucketLocation

Usage:
    python3 public_s3_buckets.py            # human + machine JSON to stdout
    python3 public_s3_buckets.py --quiet    # JSON only, no stderr progress
"""
import argparse
import sys
import boto3
from botocore.exceptions import ClientError
from reporter import make_finding, build_report, emit, eprint

CHECK_ID = "CSPM-01"
CATEGORY = "public_s3_buckets"

PUBLIC_GROUP_URIS = {
    "http://acs.amazonaws.com/groups/global/AllUsers",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
}


def _bucket_region(s3, bucket_name: str) -> str:
    try:
        loc = s3.get_bucket_location(Bucket=bucket_name)["LocationConstraint"]
        return loc or "us-east-1"
    except ClientError:
        return "unknown"


def _acl_is_public(s3, bucket_name: str) -> bool:
    acl = s3.get_bucket_acl(Bucket=bucket_name)
    for grant in acl.get("Grants", []):
        grantee = grant.get("Grantee", {})
        if grantee.get("Type") == "Group" and grantee.get("URI") in PUBLIC_GROUP_URIS:
            return True
    return False


def _policy_is_public(s3, bucket_name: str) -> bool:
    try:
        status = s3.get_bucket_policy_status(Bucket=bucket_name)
        return status["PolicyStatus"]["IsPublic"]
    except ClientError as e:
        # NoSuchBucketPolicy just means there's no policy at all -> not public via policy
        if e.response["Error"]["Code"] == "NoSuchBucketPolicy":
            return False
        raise


def _public_access_block_blocks_everything(s3, bucket_name: str) -> bool:
    try:
        pab = s3.get_public_access_block(Bucket=bucket_name)["PublicAccessBlockConfiguration"]
        return all([
            pab.get("BlockPublicAcls", False),
            pab.get("IgnorePublicAcls", False),
            pab.get("BlockPublicPolicy", False),
            pab.get("RestrictPublicBuckets", False),
        ])
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
            return False
        raise


def check_public_s3_buckets(session: boto3.Session = None, quiet: bool = False) -> list[dict]:
    session = session or boto3.Session()
    s3 = session.client("s3")
    findings = []

    buckets = s3.list_buckets().get("Buckets", [])
    if not quiet:
        eprint(f"[{CHECK_ID}] Evaluating {len(buckets)} S3 bucket(s)...")

    for b in buckets:
        name = b["Name"]
        region = _bucket_region(s3, name)
        try:
            pab_locks_down = _public_access_block_blocks_everything(s3, name)
            acl_public = False if pab_locks_down else _acl_is_public(s3, name)
            policy_public = False if pab_locks_down else _policy_is_public(s3, name)
            is_public = acl_public or policy_public

            reasons = []
            if acl_public:
                reasons.append("bucket ACL grants access to AllUsers/AuthenticatedUsers")
            if policy_public:
                reasons.append("bucket policy statement allows a public principal")

            findings.append(make_finding(
                check_id=CHECK_ID,
                category=CATEGORY,
                resource_id=name,
                resource_type="AWS::S3::Bucket",
                region=region,
                status="FAIL" if is_public else "PASS",
                severity="CRITICAL" if is_public else "LOW",
                description=(
                    f"Bucket '{name}' is publicly accessible: {', '.join(reasons)}."
                    if is_public else
                    f"Bucket '{name}' is not publicly accessible (Public Access Block "
                    f"{'fully blocks public access' if pab_locks_down else 'ACL/policy checked and clean'})."
                ),
                remediation=(
                    "Enable all four S3 Block Public Access settings for this bucket "
                    "(BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, "
                    "RestrictPublicBuckets), and remove any bucket policy statement "
                    "or ACL grant with Principal '*' or the AllUsers/AuthenticatedUsers "
                    "group unless it is deliberately a public static-website bucket, in "
                    "which case document the exception."
                ) if is_public else "",
            ))
        except ClientError as e:
            findings.append(make_finding(
                check_id=CHECK_ID, category=CATEGORY, resource_id=name,
                resource_type="AWS::S3::Bucket", region=region, status="FAIL",
                severity="MEDIUM",
                description=f"Could not fully evaluate bucket '{name}': {e}",
                remediation="Re-run with sufficient IAM permissions to evaluate this bucket.",
            ))
    return findings


def main():
    parser = argparse.ArgumentParser(description="Check for publicly accessible S3 buckets.")
    parser.add_argument("--quiet", action="store_true", help="suppress stderr progress output")
    args = parser.parse_args()

    findings = check_public_s3_buckets(quiet=args.quiet)
    report = build_report("Public S3 Buckets", findings)
    return emit(report)


if __name__ == "__main__":
    sys.exit(main())
