# Handoff — Database & Infrastructure Issues

**Date:** 2026-09-25
**Account:** 858573892697 (QLabs) · **Region:** us-east-1
**Raised from:** Deliverable 4 (EC2 OS Vulnerability Scanning & Hardening)
**Status:** Open — awaiting owner assignment

---

## Scope note

Deliverable 4 covers **EC2 OS vulnerability scanning and hardening** (Trivy + Lynis,
before/after, cross-check). That deliverable is complete and evidenced in this
directory.

Everything below was discovered while checking the RDS instances. **None of it is
part of Deliverable 4** and it is being handed off rather than fixed here.

Tracking source: `before-after-tracking.md` → `## Database Remediation — To-Do`.

---

## Changes already made on 2026-09-25 (please review)

| # | Change | Where | Why |
|---|--------|-------|-----|
| 1 | Backup retention **0 → 7 days** | AWS RDS, both instances | Approved. Closes tracking **#4 (CRITICAL)**, resolves Prowler `rds_instance_backup_enabled` FAIL |
| 2 | `main.tf` edit **reverted** — `backup_retention_period` left at `0` | `infra/breach-zone/main.tf` | Returned to committed original (`git diff` clean). **DRIFT: AWS = 7, config = 0** — a `terraform apply` would set backups back to **0**, so decide before applying |
| 3 | Manual snapshots created **then deleted** | AWS RDS | Precaution taken, removed same day to avoid storage cost |

**Snapshots deleted 2026-09-25:**
`vaultcloud-prod-db-prepatch-20260925`, `vaultcloud-prod-db-private-prepatch-20260925`

Still present: `vaultcloud-prod-db-pre-migration` (pre-existing, 2026-09-19) and the
automated backups that the new 7-day retention now creates — e.g.
`rds:vaultcloud-prod-db-2026-09-26-02-46`. The automated ones rotate out on their
own within the 7-day window.

**Not applied:** the pending `system-update` on both instances — left untouched on
purpose and **handed to the infra owner to apply**.

---

## Decision required first (blocks patching)

| Question | Options | Status |
|----------|---------|--------|
| Which RDS instance to use? | Migrate to private / fix public / keep both | **Pending** |
| `vaultcloud-prod-db-private` is not in Terraform | Import to TF / delete from console | **Pending** |

Until both are answered, patching and hardening either instance is premature.

---

## Issue list by owner

### Infra / Terraform -- `infra/breach-zone/main.tf`

| # | Issue | Sev | Status |
|---|-------|-----|--------|
| 1 | Move DB subnet group to private subnets (10.0.3.0, 10.0.4.0) | CRITICAL | Pending |
| 2 | `publicly_accessible = true` → `false` | CRITICAL | Pending |
| 3 | `storage_encrypted = false` → `true` (KMS) | CRITICAL | Pending |
| 4 | `backup_retention_period = 7` | CRITICAL | **AWS done 2026-09-25 (7 days live on both). `main.tf` still `0` -- Terraform side pending** |
| 5 | `multi_az = false` → `true` | HIGH | Pending |
| 6 | `deletion_protection = false` → `true` | HIGH | Pending |
| 7 | `auto_minor_version_upgrade = false` → `true` | MEDIUM | Pending |
| 8 | Restrict security group to app SG, port 5432 only | CRITICAL | Pending |
| 9 | Import private instance to Terraform **or** delete from console | HIGH | Pending |
| 10 | Rotate DB password — hardcoded in plaintext at `main.tf:196`; move to Secrets Manager | CRITICAL | Pending |
| — | `# TODO: add more tags` on `aws_instance.app_server` (line 142) | LOW | Pending |

Also pending: `# TODO` drift — `vaultcloud-prod-db-private` and
`vaultcloud-db-subnet-private` exist only in console, not in Terraform.

#### Terraform working state (as left on 2026-09-25)

These were encountered while attempting to sync and were **put back exactly as
found**. Resolving them is part of this handoff.

| Item | State | Action needed |
|------|-------|---------------|
| `.terraform.tfstate.lock.info` | Stale lock from **2026-09-18**, `OperationTypeApply`, `akinsile@HP-EliteBook-Folio-9470m` | **Local state cannot be force-unlocked from another process.** Remove it from the original machine, or delete the file only after confirming no apply is running |
| `.terraform/` provider directory | **Absent** | Run `terraform init` before any plan/apply |
| `terraform.tfstate` / `terraform.tfstate.backup` | Untouched, last write 2026-09-16 16:48. Removed from git tracking on 2026-09-25; both were committed despite `.gitignore` | None |
| `main.tf` | Reverted to committed original, `git diff` clean | Reconcile the backup-retention drift in row 2 above |
| `main.tf.backup` | Stale copy from 2026-09-16, still shows `backup_retention_period = 0` with older formatting. Removed from git tracking on 2026-09-25, file kept on disk | Not read by Terraform; safe to delete, but may mislead |

**CRITICAL -- hardcoded credentials:** the `provider "aws"` block at
`main.tf` lines 12-13 contains a plaintext **AWS access key ID and secret access
key**. Replace with a profile / SSO assumption and **rotate the key**; treat it as
compromised since it is committed to source.

#### CI host scan -- needs an OIDC role (account 858573892697)

`.github/workflows/trivy-gate.yml` has three jobs: container scan, runner host scan,
and an EC2 host scan that runs `vulnerability-management/ec2-host-scan.sh` over SSM.
The EC2 job authenticates with GitHub OIDC and reads the role ARN from the repository
variable `AWS_SCANNER_ROLE_ARN`. While that variable is empty the job is skipped, so
CI is green today and activates on its own once the role exists.

| Item | Detail |
|------|--------|
| Trust | `token.actions.githubusercontent.com` in account 858573892697, `aud = sts.amazonaws.com`, `sub` scoped to `repo:IsiakaOladayo/breach-zone:ref:refs/heads/main` and `repo:IsiakaOladayo/breach-zone:pull_request` |
| Policy | `ssm:SendCommand`, `ssm:GetCommandInvocation`, `ssm:ListCommands`, `ec2:DescribeInstances`, `s3:PutObject`, `s3:GetObject`, `s3:DeleteObject` on `arn:aws:s3:::vaultcloud-uploads-prod-2024/*` |
| Output | Paste the role ARN into repository variable `AWS_SCANNER_ROLE_ARN` |

The script uses presigned URLs against `vaultcloud-uploads-prod-2024` to move the
Trivy database onto the instance and the results back off it, which is why the S3
statements are in the policy.

The existing `cspm-github-actions-deploy` role from
`infra/posture-management/bootstrap/oidc.tf` cannot be reused: its policy grants only
Config, S3, IAM and SNS, with no SSM or EC2 permissions.

AWS allows one OIDC provider per account. Check for an existing
`token.actions.githubusercontent.com` provider in 858573892697 and import it rather
than creating a second one.

This role uses no long-lived keys, so nothing static is stored in GitHub.

---

### Cloud Security

| # | Issue | Sev | Status |
|---|-------|-----|--------|
| 11 | `/vaultcloud/prod/db_password` is plaintext `String` → should be `SecureString` | CRITICAL | Pending |
| 12 | `/vaultcloud/prod/stripe_secret` → `SecureString` | CRITICAL | Pending |
| 13 | `/vaultcloud/prod/admin_token` → `SecureString` | CRITICAL | Pending |
| 14 | `/vaultcloud/prod/webhook_secret` → `SecureString` | CRITICAL | Pending |

**Security group `vaultcloud-db-sg` (`sg-059591e29c62e2064`)** — shared by *both*
RDS instances, ingress is `protocol -1` from `0.0.0.0/0` (all ports, all traffic,
internet-wide). Flagged repeatedly in Prowler output. See infra item #8.

---

### Application -- `app/app.py`, `docker-compose.yml`

| # | Issue | Sev | Status |
|---|-------|-----|--------|
| 15 | SQL injection — string-formatted query (line 96) | CRITICAL | Pending |
| 16 | Plaintext password comparison → hash with bcrypt | CRITICAL | Pending |
| 17 | Remove `/debug/config` (leaks `SECRET_KEY`, `ADMIN_TOKEN`, full env) | CRITICAL | Pending |
| 18 | Remove `/debug/sql` (arbitrary SQL execution) | CRITICAL | Pending |
| 19 | `/api/v1/admin/users` returns passwords and api_keys → exclude | HIGH | Pending |
| 20 | Remove Adminer from `docker-compose.yml` (`# TODO: remove this before go-live`, line 35) | MEDIUM | Pending |
| 21 | Add auth to Redis (currently no password) | MEDIUM | Pending |
| — | `# TODO: add auth check here` on `GET /api/v1/accounts` (line 85) | HIGH | Pending |

---

### Infra -- pending RDS maintenance (not applied)

Both instances have a pending action:

```
system-update — "New Operating System update is available"
```

| Instance | Class | Multi-AZ | Public | Maintenance window | Auto minor |
|---|---|---|---|---|---|
| `vaultcloud-prod-db` | db.t3.micro | No | **Yes** | thu 05:50–06:20 UTC | `false` |
| `vaultcloud-prod-db-private` | db.m7g.large | Yes | No | thu 05:50–06:20 UTC | `true` |

No engine upgrade is available (`PostgreSQL 17.11` has no upgrade targets), so this
is an OS-level patch only.

**To apply** (after the two decisions above are resolved):

```bash
export AWS_PROFILE=QLabs AWS_DEFAULT_REGION=us-east-1

# immediate (vaultcloud-prod-db is single-AZ -> outage until restart completes)
aws rds apply-pending-maintenance-action \
  --resource-identifier arn:aws:rds:us-east-1:858573892697:db:vaultcloud-prod-db \
  --apply-action system-update --opt-in-type immediate

# or defer to the configured window (safer)
aws rds apply-pending-maintenance-action \
  --resource-identifier arn:aws:rds:us-east-1:858573892697:db:vaultcloud-prod-db \
  --apply-action system-update --opt-in-type next-maintenance
```

> **Snapshot first** — the earlier prepatch snapshots were deleted on 2026-09-25,
> so take a fresh one immediately before patching:
>
> ```bash
> aws rds create-db-snapshot --db-snapshot-identifier vaultcloud-prod-db-prepatch-YYYYMMDD \
>   --db-instance-identifier vaultcloud-prod-db
> ```
>
> Rollback = restore from that snapshot.

---

## Live-traffic note (why this wasn't urgent)

`DatabaseConnections` over the last 24h:

- `vaultcloud-prod-db` — maximum **1** (average 0.0007)
- `vaultcloud-prod-db-private` — maximum **0**

Nothing in this repository connects to either database: `app/app.py` reads
`DB_PATH=/app/data/vaultcloud.db` (SQLite), and there is no Postgres service,
`DB_HOST`, or `DATABASE_URL` anywhere in the codebase. The `db_endpoint` Terraform
output is published but unconsumed.

---

## Not part of this handoff

Deliverable 4 evidence — already complete in this directory:

`results/ec2-scan-summary.json` · `results/ec2-host-scan-baseline.txt` · `ec2-scan-crosscheck.md` ·
`results/lynis-final.json` · `ec2-remediation-status.md` · `results/trivy-rescan-raw.json` ·
`before-after-tracking.md` · `deliverable4-ec2-evidence.md` · `ec2-scan-report.html`
