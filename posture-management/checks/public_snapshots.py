#!/usr/bin/env python3
"""
Check: CSPM-07 — Public Snapshots
Category: Storage Exposure

What this checks, and why:
    A public EBS or RDS snapshot is a full, restorable copy of a disk or
    database, sitting outside the encryption/network controls of the live
    resource entirely. It is a much less visible exposure vector than a
    public S3 bucket (CSPM-01) or open security group (CSPM-02) because
    nobody watches "snapshots" the way they watch "buckets," which is
    exactly why it earns its own dedicated check rather than being folded
    into CSPM-01.

Required IAM permissions:
    ec2:DescribeSnapshots, ec2:DescribeSnapshotAttribute, ec2:DescribeRegions,
    rds:DescribeDBSnapshots, rds:DescribeDBSnapshotAttributes

Usage:
    python3 public_snapshots.py
"""
import argparse
import sys
import boto3
from reporter import make_finding, build_report, emit, eprint

CHECK_ID = "CSPM-07"
CATEGORY = "public_snapshots"


def _check_ebs_snapshots(session, quiet) -> list[dict]:
    ec2_global = session.client("ec2", region_name="us-east-1")
    account_id = session.client("sts").get_caller_identity()["Account"]
    regions = [r["RegionName"] for r in ec2_global.describe_regions(AllRegions=False)["Regions"]]
    findings = []
    for reg in regions:
        ec2 = session.client("ec2", region_name=reg)
        try:
            paginator = ec2.get_paginator("describe_snapshots")
            snapshots = [s for page in paginator.paginate(OwnerIds=["self"]) for s in page["Snapshots"]]
        except Exception as e:
            if not quiet:
                eprint(f"[{CHECK_ID}] Skipping EBS snapshots in {reg}: {e}")
            continue
        if snapshots and not quiet:
            eprint(f"[{CHECK_ID}] {reg}: checking {len(snapshots)} EBS snapshot(s)...")
        for snap in snapshots:
            attr = ec2.describe_snapshot_attribute(
                SnapshotId=snap["SnapshotId"], Attribute="createVolumePermission"
            )
            is_public = any(p.get("Group") == "all" for p in attr.get("CreateVolumePermissions", []))
            findings.append(make_finding(
                check_id=CHECK_ID, category=CATEGORY, resource_id=snap["SnapshotId"],
                resource_type="AWS::EC2::Snapshot", region=reg,
                status="FAIL" if is_public else "PASS",
                severity="CRITICAL" if is_public else "LOW",
                description=f"EBS snapshot {snap['SnapshotId']} (volume {snap.get('VolumeId')}) "
                            f"is {'PUBLIC — restorable by any AWS account' if is_public else 'private'}.",
                remediation="" if not is_public else
                            f"Remove the 'all' group create-volume-permission from this snapshot "
                            f"immediately. If it needs to be shared, share explicitly with "
                            f"specific account IDs instead (e.g. {account_id} plus named accounts).",
            ))
    return findings


def _check_rds_snapshots(session, quiet) -> list[dict]:
    ec2_global = session.client("ec2", region_name="us-east-1")
    regions = [r["RegionName"] for r in ec2_global.describe_regions(AllRegions=False)["Regions"]]
    findings = []
    for reg in regions:
        rds = session.client("rds", region_name=reg)
        try:
            paginator = rds.get_paginator("describe_db_snapshots")
            snapshots = [s for page in paginator.paginate() for s in page["DBSnapshots"]]
        except Exception as e:
            if not quiet:
                eprint(f"[{CHECK_ID}] Skipping RDS snapshots in {reg}: {e}")
            continue
        if snapshots and not quiet:
            eprint(f"[{CHECK_ID}] {reg}: checking {len(snapshots)} RDS snapshot(s)...")
        for snap in snapshots:
            attrs = rds.describe_db_snapshot_attributes(
                DBSnapshotIdentifier=snap["DBSnapshotIdentifier"]
            )["DBSnapshotAttributesResult"]["DBSnapshotAttributes"]
            is_public = any(
                a["AttributeName"] == "restore" and "all" in a.get("AttributeValues", [])
                for a in attrs
            )
            findings.append(make_finding(
                check_id=CHECK_ID, category=CATEGORY, resource_id=snap["DBSnapshotIdentifier"],
                resource_type="AWS::RDS::DBSnapshot", region=reg,
                status="FAIL" if is_public else "PASS",
                severity="CRITICAL" if is_public else "LOW",
                description=f"RDS snapshot {snap['DBSnapshotIdentifier']} is "
                            f"{'PUBLIC — restorable by any AWS account' if is_public else 'private'}.",
                remediation="" if not is_public else
                            "Remove 'all' from the snapshot's restore attribute values "
                            "immediately; share with specific account IDs instead if needed.",
            ))
    return findings


def check_public_snapshots(session: boto3.Session = None, quiet: bool = False) -> list[dict]:
    session = session or boto3.Session()
    return _check_ebs_snapshots(session, quiet) + _check_rds_snapshots(session, quiet)


def main():
    parser = argparse.ArgumentParser(description="Check EBS and RDS snapshots for public exposure.")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    findings = check_public_snapshots(quiet=args.quiet)
    report = build_report("Public Snapshots", findings)
    return emit(report)


if __name__ == "__main__":
    sys.exit(main())
