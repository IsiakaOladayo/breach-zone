#!/usr/bin/env python3
"""
drift_test.py — Phase 3, Workflow Step 4

"Prove drift detection works. Deliberately re-introduce one misconfiguration
(e.g., make a bucket public again) and time how long it takes your posture
stack to flag it. Target: under 15 minutes. Record the actual time."

This script does the full loop for the S3 public-bucket case, using
checks/public_s3_buckets.py as the "posture stack" being timed (the same
approach applies to any other check by swapping CHECK_FN):

  1. Confirm the target bucket is currently PASS-ing (private) — refuses to
     run the drift test on a bucket that's already public, since that would
     produce a meaningless (or negative) timing result.
  2. Record t0, then deliberately disable the bucket's Block Public Access
     settings and set a public-read bucket policy.
  3. Poll check_public_s3_buckets() every --poll-seconds until it reports
     this bucket as FAIL, recording t1.
  4. Immediately re-lock the bucket down (restore Block Public Access +
     remove the public policy) regardless of outcome, so the drift is never
     left open longer than necessary.
  5. Write a timestamped result file to evidence/drift-tests/.

SAFETY: this script requires --confirm to actually flip the bucket public.
Without it, it only prints what it would do. This script always re-locks
the bucket in a `finally` block, even on error or Ctrl-C.

Required IAM permissions (beyond public_s3_buckets.py's):
    s3:PutBucketPublicAccessBlock, s3:PutBucketPolicy, s3:DeleteBucketPolicy

Usage:
    python3 drift_test.py --bucket my-test-bucket --confirm
    python3 drift_test.py --bucket my-test-bucket --confirm --poll-seconds 30 --timeout-seconds 900
"""
import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone

import boto3

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "checks"))
from public_s3_buckets import check_public_s3_buckets  # noqa: E402

DEFAULT_POLL_SECONDS = 30
DEFAULT_TIMEOUT_SECONDS = 900  # 15 minutes, matching the gate in the brief


def _bucket_status(bucket_name: str, session: boto3.Session) -> str:
    findings = check_public_s3_buckets(session=session, quiet=True)
    for f in findings:
        if f["resource_id"] == bucket_name:
            return f["status"]
    raise RuntimeError(f"Bucket '{bucket_name}' not found by check_public_s3_buckets — "
                        f"check the name and your credentials' region/account.")


def _make_public(s3, bucket_name: str):
    s3.put_public_access_block(
        Bucket=bucket_name,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": False, "IgnorePublicAcls": False,
            "BlockPublicPolicy": False, "RestrictPublicBuckets": False,
        },
    )
    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "PublicReadForDriftTest",
            "Effect": "Allow",
            "Principal": "*",
            "Action": "s3:GetObject",
            "Resource": f"arn:aws:s3:::{bucket_name}/*",
        }],
    }
    s3.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(policy))


def _re_lock_down(s3, bucket_name: str):
    s3.put_public_access_block(
        Bucket=bucket_name,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True, "IgnorePublicAcls": True,
            "BlockPublicPolicy": True, "RestrictPublicBuckets": True,
        },
    )
    try:
        s3.delete_bucket_policy(Bucket=bucket_name)
    except s3.exceptions.ClientError:
        pass  # no policy left to delete, that's fine


def main():
    parser = argparse.ArgumentParser(description="Time how long the posture stack takes to flag a "
                                                    "deliberately re-introduced S3 public-bucket misconfig.")
    parser.add_argument("--bucket", required=True, help="name of an S3 bucket you own, for testing ONLY")
    parser.add_argument("--confirm", action="store_true",
                         help="actually flip the bucket public; without this, dry-run only")
    parser.add_argument("--poll-seconds", type=int, default=DEFAULT_POLL_SECONDS)
    parser.add_argument("--timeout-seconds", type=int, default=DEFAULT_TIMEOUT_SECONDS)
    args = parser.parse_args()

    session = boto3.Session()
    s3 = session.client("s3")

    print(f"Checking current status of bucket '{args.bucket}'...")
    current_status = _bucket_status(args.bucket, session)
    if current_status == "FAIL":
        print(f"ERROR: bucket '{args.bucket}' is already publicly flagged (FAIL). "
              f"Fix it first so this test measures a real transition, not a no-op.", file=sys.stderr)
        return 1
    print(f"Confirmed: '{args.bucket}' currently PASSes (private). Proceeding.")

    if not args.confirm:
        print("\nDRY RUN (no --confirm passed). Would now:")
        print(f"  1. Disable Block Public Access + attach a public-read policy on '{args.bucket}'")
        print(f"  2. Poll check_public_s3_buckets() every {args.poll_seconds}s until it reports FAIL")
        print(f"  3. Re-lock the bucket down immediately")
        print(f"  4. Write timing evidence to evidence/drift-tests/")
        print("\nRe-run with --confirm to actually execute the test.")
        return 0

    t0 = time.monotonic()
    t0_wall = datetime.now(timezone.utc)
    detected_at = None
    detected_at_wall = None

    try:
        print(f"\n[{t0_wall.isoformat()}] Deliberately making '{args.bucket}' public...")
        _make_public(s3, args.bucket)
        print("Misconfiguration introduced. Polling for detection...")

        elapsed = 0
        while elapsed < args.timeout_seconds:
            time.sleep(args.poll_seconds)
            elapsed = time.monotonic() - t0
            status = _bucket_status(args.bucket, session)
            print(f"  t+{elapsed:6.1f}s: posture stack reports status={status}")
            if status == "FAIL":
                detected_at = time.monotonic()
                detected_at_wall = datetime.now(timezone.utc)
                break

        if detected_at is None:
            print(f"\nNOT DETECTED within {args.timeout_seconds}s timeout. This is a real finding, "
                  f"not something to hide — report it honestly and investigate why.", file=sys.stderr)
            result = {"detected": False, "timeout_seconds": args.timeout_seconds}
        else:
            detection_time_seconds = round(detected_at - t0, 1)
            print(f"\nDETECTED after {detection_time_seconds}s "
                  f"({'within' if detection_time_seconds < 900 else 'OUTSIDE'} the 15-minute target).")
            result = {
                "detected": True,
                "detection_time_seconds": detection_time_seconds,
                "target_seconds": 900,
                "met_target": detection_time_seconds < 900,
            }

        result.update({
            "bucket": args.bucket,
            "misconfiguration_introduced_utc": t0_wall.isoformat(),
            "detected_utc": detected_at_wall.isoformat() if detected_at_wall else None,
            "poll_interval_seconds": args.poll_seconds,
        })

        out_dir = "evidence/drift-tests"
        os.makedirs(out_dir, exist_ok=True)
        out_path = os.path.join(out_dir, f"drift-test-{t0_wall.strftime('%Y%m%dT%H%M%SZ')}.json")
        with open(out_path, "w") as f:
            json.dump(result, f, indent=2)
        print(f"Result written to: {out_path}")

        return 0 if result.get("detected") and result.get("met_target", True) else 1

    finally:
        print(f"\nRe-locking bucket '{args.bucket}' down regardless of outcome...")
        _re_lock_down(s3, args.bucket)
        print("Bucket re-locked (Block Public Access restored, public policy removed).")


if __name__ == "__main__":
    sys.exit(main())
