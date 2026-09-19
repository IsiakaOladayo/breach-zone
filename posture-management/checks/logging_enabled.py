#!/usr/bin/env python3
"""
Check: CSPM-05 — Logging Enabled
Category: Observability / Audit Trail

What this checks, and why:
    You cannot investigate an incident (Deliverable 6) you have no log of.
    This check verifies three independent logging layers, because each
    covers a different blast radius:
      1. CloudTrail — is there at least one multi-region trail that is
         actually logging right now (IsLogging == True), not just defined?
      2. VPC Flow Logs — does every VPC have flow logs enabled? (network
         forensics depend on this)
      3. S3 server access logging — is it enabled per-bucket? (useful for
         detecting anonymous/unexpected object access, separate from
         CloudTrail data events which are often not enabled by default)

Required IAM permissions:
    cloudtrail:DescribeTrails, cloudtrail:GetTrailStatus,
    ec2:DescribeVpcs, ec2:DescribeFlowLogs, ec2:DescribeRegions,
    s3:ListAllMyBuckets, s3:GetBucketLogging

Usage:
    python3 logging_enabled.py
"""
import argparse
import sys
import boto3
from reporter import make_finding, build_report, emit, eprint

CHECK_ID = "CSPM-05"
CATEGORY = "logging_enabled"


def _check_cloudtrail(session, quiet) -> list[dict]:
    ct = session.client("cloudtrail", region_name="us-east-1")
    findings = []
    trails = ct.describe_trails(includeShadowTrails=True).get("trailList", [])
    if not quiet:
        eprint(f"[{CHECK_ID}] Found {len(trails)} CloudTrail trail(s), checking logging status...")

    any_active_multiregion = False
    for t in trails:
        status = ct.get_trail_status(Name=t["TrailARN"])
        is_logging = status.get("IsLogging", False)
        if is_logging and t.get("IsMultiRegionTrail"):
            any_active_multiregion = True
        findings.append(make_finding(
            check_id=CHECK_ID, category=CATEGORY, resource_id=t["Name"],
            resource_type="AWS::CloudTrail::Trail", region=t.get("HomeRegion", "unknown"),
            status="PASS" if is_logging else "FAIL",
            severity="LOW" if is_logging else "CRITICAL",
            description=f"Trail '{t['Name']}' (multi-region={t.get('IsMultiRegionTrail')}) "
                        f"is {'actively logging' if is_logging else 'NOT logging'}.",
            remediation="" if is_logging else "Start logging on this trail (aws cloudtrail start-logging).",
        ))

    if not trails or not any_active_multiregion:
        findings.append(make_finding(
            check_id=CHECK_ID, category=CATEGORY, resource_id="account-level",
            resource_type="AWS::CloudTrail::Account", region="global", status="FAIL",
            severity="CRITICAL",
            description="No active multi-region CloudTrail trail was found for this account. "
                        "API activity in any region without one is not being captured.",
            remediation="Create a multi-region trail delivering to a dedicated logging bucket "
                        "with log file validation enabled, and confirm start-logging succeeded.",
        ))
    return findings


def _check_vpc_flow_logs(session, quiet) -> list[dict]:
    ec2_global = session.client("ec2", region_name="us-east-1")
    regions = [r["RegionName"] for r in ec2_global.describe_regions(AllRegions=False)["Regions"]]
    findings = []
    for reg in regions:
        ec2 = session.client("ec2", region_name=reg)
        try:
            vpcs = ec2.describe_vpcs()["Vpcs"]
            flow_logs = ec2.describe_flow_logs()["FlowLogs"]
        except Exception as e:
            if not quiet:
                eprint(f"[{CHECK_ID}] Skipping {reg}: {e}")
            continue
        if vpcs and not quiet:
            eprint(f"[{CHECK_ID}] {reg}: checking flow logs on {len(vpcs)} VPC(s)...")
        vpcs_with_logs = {fl["ResourceId"] for fl in flow_logs if fl.get("FlowLogStatus") == "ACTIVE"}
        for v in vpcs:
            has_logs = v["VpcId"] in vpcs_with_logs
            findings.append(make_finding(
                check_id=CHECK_ID, category=CATEGORY, resource_id=v["VpcId"],
                resource_type="AWS::EC2::VPC", region=reg,
                status="PASS" if has_logs else "FAIL",
                severity="LOW" if has_logs else "HIGH",
                description=f"VPC {v['VpcId']} {'has' if has_logs else 'has NO'} active flow logs.",
                remediation="" if has_logs else
                            "Enable VPC Flow Logs for this VPC, delivering to CloudWatch Logs "
                            "or S3, capturing ALL traffic (accepted + rejected).",
            ))
    return findings


def _check_s3_access_logging(session, quiet) -> list[dict]:
    s3 = session.client("s3")
    findings = []
    buckets = s3.list_buckets().get("Buckets", [])
    if not quiet:
        eprint(f"[{CHECK_ID}] Checking access logging on {len(buckets)} S3 bucket(s)...")
    for b in buckets:
        name = b["Name"]
        logging_cfg = s3.get_bucket_logging(Bucket=name)
        enabled = "LoggingEnabled" in logging_cfg
        findings.append(make_finding(
            check_id=CHECK_ID, category=CATEGORY, resource_id=name,
            resource_type="AWS::S3::Bucket", region="global",
            status="PASS" if enabled else "FAIL",
            severity="LOW" if enabled else "MEDIUM",
            description=f"Bucket '{name}' {'has' if enabled else 'has NO'} server access logging enabled.",
            remediation="" if enabled else "Enable S3 server access logging to a dedicated logging bucket.",
        ))
    return findings


def check_logging_enabled(session: boto3.Session = None, quiet: bool = False) -> list[dict]:
    session = session or boto3.Session()
    return (_check_cloudtrail(session, quiet)
            + _check_vpc_flow_logs(session, quiet)
            + _check_s3_access_logging(session, quiet))


def main():
    parser = argparse.ArgumentParser(description="Check CloudTrail, VPC Flow Logs, and S3 access logging.")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    findings = check_logging_enabled(quiet=args.quiet)
    report = build_report("Logging Enabled", findings)
    return emit(report)


if __name__ == "__main__":
    sys.exit(main())
