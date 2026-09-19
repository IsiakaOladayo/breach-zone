#!/usr/bin/env python3
"""
Check: CSPM-02 — Open Security Groups
Category: Network Exposure

What this checks, and why:
    Flags any security group with an ingress rule that allows 0.0.0.0/0
    (any IPv4) or ::/0 (any IPv6). A rule open on a "sensitive" port
    (22/SSH, 3389/RDP, 3306/MySQL, 5432/Postgres, 1433/MSSQL, 6379/Redis,
    9200/Elasticsearch, 27017/MongoDB) is CRITICAL; any other wide-open
    port is HIGH, since "any port to anywhere" is still a real exposure
    even if it happens to not be one of the classic risky ports.

Required IAM permissions:
    ec2:DescribeSecurityGroups, ec2:DescribeRegions

Usage:
    python3 open_security_groups.py
    python3 open_security_groups.py --region us-east-1   # limit to one region
"""
import argparse
import sys
import boto3
from reporter import make_finding, build_report, emit, eprint

CHECK_ID = "CSPM-02"
CATEGORY = "open_security_groups"

SENSITIVE_PORTS = {22, 3389, 3306, 5432, 1433, 6379, 9200, 27017}
OPEN_CIDRS = {"0.0.0.0/0", "::/0"}


def _port_range_str(rule: dict) -> str:
    frm = rule.get("FromPort")
    to = rule.get("ToPort")
    if frm is None and to is None:
        return "ALL"
    if frm == to:
        return str(frm)
    return f"{frm}-{to}"


def _rule_hits_sensitive_port(rule: dict) -> bool:
    frm, to = rule.get("FromPort"), rule.get("ToPort")
    if frm is None and to is None:
        return True  # "ALL" protocol/ports covers sensitive ports too
    if frm is None or to is None:
        return False
    return any(frm <= p <= to for p in SENSITIVE_PORTS)


def _get_regions(session: boto3.Session) -> list[str]:
    ec2 = session.client("ec2", region_name="us-east-1")
    return [r["RegionName"] for r in ec2.describe_regions(AllRegions=False)["Regions"]]


def check_open_security_groups(session: boto3.Session = None, region: str = None,
                                quiet: bool = False) -> list[dict]:
    session = session or boto3.Session()
    regions = [region] if region else _get_regions(session)
    findings = []

    for reg in regions:
        ec2 = session.client("ec2", region_name=reg)
        try:
            sgs = ec2.describe_security_groups()["SecurityGroups"]
        except Exception as e:
            if not quiet:
                eprint(f"[{CHECK_ID}] Skipping region {reg}: {e}")
            continue

        if not quiet:
            eprint(f"[{CHECK_ID}] {reg}: evaluating {len(sgs)} security group(s)...")

        for sg in sgs:
            open_rules = []
            for rule in sg.get("IpPermissions", []):
                cidrs = [r["CidrIp"] for r in rule.get("IpRanges", []) if r.get("CidrIp") in OPEN_CIDRS]
                cidrs += [r["CidrIpv6"] for r in rule.get("Ipv6Ranges", []) if r.get("CidrIpv6") in OPEN_CIDRS]
                if cidrs:
                    open_rules.append((rule, cidrs))

            if not open_rules:
                findings.append(make_finding(
                    check_id=CHECK_ID, category=CATEGORY, resource_id=sg["GroupId"],
                    resource_type="AWS::EC2::SecurityGroup", region=reg, status="PASS",
                    severity="LOW",
                    description=f"Security group {sg['GroupId']} ({sg.get('GroupName')}) "
                                f"has no ingress rule open to 0.0.0.0/0 or ::/0.",
                ))
                continue

            for rule, cidrs in open_rules:
                sensitive = _rule_hits_sensitive_port(rule)
                port_str = _port_range_str(rule)
                proto = rule.get("IpProtocol", "-1")
                findings.append(make_finding(
                    check_id=CHECK_ID, category=CATEGORY, resource_id=sg["GroupId"],
                    resource_type="AWS::EC2::SecurityGroup", region=reg, status="FAIL",
                    severity="CRITICAL" if sensitive else "HIGH",
                    description=(
                        f"Security group {sg['GroupId']} ({sg.get('GroupName')}) allows "
                        f"protocol={proto} port(s)={port_str} from {'/'.join(cidrs)}."
                    ),
                    remediation=(
                        "Restrict this rule's source CIDR to specific known IP ranges "
                        "(office VPN, bastion, or a security-group reference) instead of "
                        "0.0.0.0/0 or ::/0. For SSH/RDP, prefer Session Manager / a bastion "
                        "with no inbound rule at all."
                    ),
                ))
    return findings


def main():
    parser = argparse.ArgumentParser(description="Check for security groups open to the world.")
    parser.add_argument("--region", default=None, help="limit check to a single region")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    findings = check_open_security_groups(region=args.region, quiet=args.quiet)
    report = build_report("Open Security Groups", findings)
    return emit(report)


if __name__ == "__main__":
    sys.exit(main())
