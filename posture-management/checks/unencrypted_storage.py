#!/usr/bin/env python3
"""
Check: CSPM-03 — Unencrypted Storage
Category: Data Protection

What this checks, and why:
    Encryption-at-rest is the single control that limits blast radius if a
    disk, snapshot, or bucket is ever exposed by mistake (see CSPM-01 and
    CSPM-07). This check covers the three storage types this environment
    actually uses: S3 buckets (default encryption config), EBS volumes
    (Encrypted attribute), and RDS instances (StorageEncrypted attribute).

Required IAM permissions:
    s3:ListAllMyBuckets, s3:GetEncryptionConfiguration,
    ec2:DescribeVolumes, ec2:DescribeRegions,
    rds:DescribeDBInstances

Usage:
    python3 unencrypted_storage.py
"""
import argparse
import sys
import boto3
from botocore.exceptions import ClientError
from reporter import make_finding, build_report, emit, eprint

CHECK_ID = "CSPM-03"
CATEGORY = "unencrypted_storage"


def _check_s3(session, quiet) -> list[dict]:
    s3 = session.client("s3")
    findings = []
    buckets = s3.list_buckets().get("Buckets", [])
    if not quiet:
        eprint(f"[{CHECK_ID}] Checking encryption on {len(buckets)} S3 bucket(s)...")
    for b in buckets:
        name = b["Name"]
        try:
            s3.get_bucket_encryption(Bucket=name)
            encrypted = True
        except ClientError as e:
            if e.response["Error"]["Code"] == "ServerSideEncryptionConfigurationNotFoundError":
                encrypted = False
            else:
                encrypted = None  # couldn't determine
        findings.append(make_finding(
            check_id=CHECK_ID, category=CATEGORY, resource_id=name,
            resource_type="AWS::S3::Bucket", region="global",
            status="PASS" if encrypted else "FAIL",
            severity="LOW" if encrypted else "HIGH",
            description=f"Bucket '{name}' {'has' if encrypted else 'has no'} default "
                        f"server-side encryption configured."
                        if encrypted is not None else f"Could not determine encryption state for '{name}'.",
            remediation="" if encrypted else "Enable default bucket encryption (SSE-S3 or SSE-KMS).",
        ))
    return findings


def _check_ebs(session, quiet) -> list[dict]:
    ec2_global = session.client("ec2", region_name="us-east-1")
    regions = [r["RegionName"] for r in ec2_global.describe_regions(AllRegions=False)["Regions"]]
    findings = []
    for reg in regions:
        ec2 = session.client("ec2", region_name=reg)
        try:
            paginator = ec2.get_paginator("describe_volumes")
            volumes = [v for page in paginator.paginate() for v in page["Volumes"]]
        except Exception as e:
            if not quiet:
                eprint(f"[{CHECK_ID}] Skipping EBS in {reg}: {e}")
            continue
        if volumes and not quiet:
            eprint(f"[{CHECK_ID}] {reg}: checking {len(volumes)} EBS volume(s)...")
        for v in volumes:
            findings.append(make_finding(
                check_id=CHECK_ID, category=CATEGORY, resource_id=v["VolumeId"],
                resource_type="AWS::EC2::Volume", region=reg,
                status="PASS" if v.get("Encrypted") else "FAIL",
                severity="LOW" if v.get("Encrypted") else "HIGH",
                description=f"EBS volume {v['VolumeId']} is "
                            f"{'encrypted' if v.get('Encrypted') else 'NOT encrypted'}.",
                remediation="" if v.get("Encrypted") else
                            "Create an encrypted snapshot of this volume, then a new encrypted "
                            "volume from it, and swap it in (EBS encryption cannot be toggled in place).",
            ))
    return findings


def _check_rds(session, quiet) -> list[dict]:
    ec2_global = session.client("ec2", region_name="us-east-1")
    regions = [r["RegionName"] for r in ec2_global.describe_regions(AllRegions=False)["Regions"]]
    findings = []
    for reg in regions:
        rds = session.client("rds", region_name=reg)
        try:
            paginator = rds.get_paginator("describe_db_instances")
            instances = [i for page in paginator.paginate() for i in page["DBInstances"]]
        except Exception as e:
            if not quiet:
                eprint(f"[{CHECK_ID}] Skipping RDS in {reg}: {e}")
            continue
        if instances and not quiet:
            eprint(f"[{CHECK_ID}] {reg}: checking {len(instances)} RDS instance(s)...")
        for i in instances:
            findings.append(make_finding(
                check_id=CHECK_ID, category=CATEGORY, resource_id=i["DBInstanceIdentifier"],
                resource_type="AWS::RDS::DBInstance", region=reg,
                status="PASS" if i.get("StorageEncrypted") else "FAIL",
                severity="LOW" if i.get("StorageEncrypted") else "CRITICAL",
                description=f"RDS instance {i['DBInstanceIdentifier']} storage is "
                            f"{'encrypted' if i.get('StorageEncrypted') else 'NOT encrypted'}.",
                remediation="" if i.get("StorageEncrypted") else
                            "RDS storage encryption cannot be enabled in place: snapshot the "
                            "instance, copy the snapshot with encryption enabled, and restore "
                            "from the encrypted copy during a maintenance window.",
            ))
    return findings


def check_unencrypted_storage(session: boto3.Session = None, quiet: bool = False) -> list[dict]:
    session = session or boto3.Session()
    return _check_s3(session, quiet) + _check_ebs(session, quiet) + _check_rds(session, quiet)


def main():
    parser = argparse.ArgumentParser(description="Check S3/EBS/RDS for missing encryption at rest.")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    findings = check_unencrypted_storage(quiet=args.quiet)
    report = build_report("Unencrypted Storage", findings)
    return emit(report)


if __name__ == "__main__":
    sys.exit(main())
