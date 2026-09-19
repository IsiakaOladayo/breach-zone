terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

data "aws_caller_identity" "current" {}

# ---------------------------------------------------------------------------
# Prerequisites: AWS Config needs a Configuration Recorder + Delivery Channel
# before any managed rule will actually evaluate anything. These are easy to
# forget and the #1 reason a freshly-deployed Config rule shows
# "no results available" instead of a compliance status.
# ---------------------------------------------------------------------------

resource "aws_s3_bucket" "config_bucket" {
  bucket = var.config_bucket_name
  tags   = { Environment = var.environment_tag }
}

resource "aws_s3_bucket_public_access_block" "config_bucket" {
  bucket                  = aws_s3_bucket.config_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "config_bucket" {
  bucket = aws_s3_bucket.config_bucket.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_policy" "config_bucket" {
  bucket = aws_s3_bucket.config_bucket.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AWSConfigBucketPermissionsCheck"
        Effect    = "Allow"
        Principal = { Service = "config.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.config_bucket.arn
      },
      {
        Sid       = "AWSConfigBucketDelivery"
        Effect    = "Allow"
        Principal = { Service = "config.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.config_bucket.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/Config/*"
        Condition = {
          StringEquals = { "s3:x-amz-acl" = "bucket-owner-full-control" }
        }
      }
    ]
  })
}

resource "aws_sns_topic" "config_notifications" {
  name = var.sns_topic_name
  tags = { Environment = var.environment_tag }
}

resource "aws_iam_role" "config_role" {
  name = "cspm-aws-config-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "config.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
  tags = { Environment = var.environment_tag }
}

resource "aws_iam_role_policy_attachment" "config_role_managed" {
  role       = aws_iam_role.config_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
}

resource "aws_iam_role_policy" "config_role_s3_delivery" {
  name = "cspm-config-s3-delivery"
  role = aws_iam_role.config_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:PutObject", "s3:GetBucketAcl"]
      Resource = [aws_s3_bucket.config_bucket.arn, "${aws_s3_bucket.config_bucket.arn}/*"]
    }]
  })
}

resource "aws_config_configuration_recorder" "recorder" {
  name     = "cspm-config-recorder"
  role_arn = aws_iam_role.config_role.arn
  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }
}

resource "aws_config_delivery_channel" "channel" {
  name           = "cspm-config-delivery-channel"
  s3_bucket_name = aws_s3_bucket.config_bucket.id
  sns_topic_arn  = aws_sns_topic.config_notifications.arn
  depends_on     = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_configuration_recorder_status" "recorder_status" {
  name       = aws_config_configuration_recorder.recorder.name
  is_enabled = true
  depends_on = [aws_config_delivery_channel.channel]
}

# ---------------------------------------------------------------------------
# Managed rules — one per highest-risk category identified in Phase 1/3.
# Each maps directly to one of the 8 custom check scripts, so the check
# script and the Config rule act as two independent detection paths for the
# same risk (useful for cross-validating your own script's logic).
# ---------------------------------------------------------------------------

# Maps to checks/public_s3_buckets.py
resource "aws_config_config_rule" "s3_public_read" {
  name = "cspm-s3-bucket-public-read-prohibited"
  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_PUBLIC_READ_PROHIBITED"
  }
  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "s3_public_write" {
  name = "cspm-s3-bucket-public-write-prohibited"
  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_PUBLIC_WRITE_PROHIBITED"
  }
  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "s3_ssl_only" {
  name = "cspm-s3-bucket-ssl-requests-only"
  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_SSL_REQUESTS_ONLY"
  }
  depends_on = [aws_config_configuration_recorder.recorder]
}

# Maps to checks/open_security_groups.py
resource "aws_config_config_rule" "restricted_ssh" {
  name = "cspm-restricted-ssh"
  source {
    owner             = "AWS"
    source_identifier = "INCOMING_SSH_DISABLED"
  }
  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "restricted_common_ports" {
  name = "cspm-restricted-common-ports"
  source {
    owner             = "AWS"
    source_identifier = "RESTRICTED_INCOMING_TRAFFIC"
  }
  input_parameters = jsonencode({
    blockedPort1 = "3389"
    blockedPort2 = "3306"
    blockedPort3 = "5432"
    blockedPort4 = "6379"
  })
  depends_on = [aws_config_configuration_recorder.recorder]
}

# Maps to checks/unencrypted_storage.py
resource "aws_config_config_rule" "ebs_encrypted" {
  name = "cspm-encrypted-volumes"
  source {
    owner             = "AWS"
    source_identifier = "ENCRYPTED_VOLUMES"
  }
  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "rds_encrypted" {
  name = "cspm-rds-storage-encrypted"
  source {
    owner             = "AWS"
    source_identifier = "RDS_STORAGE_ENCRYPTED"
  }
  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "s3_encrypted" {
  name = "cspm-s3-default-encryption-kms"
  source {
    owner             = "AWS"
    source_identifier = "S3_DEFAULT_ENCRYPTION_KMS"
  }
  depends_on = [aws_config_configuration_recorder.recorder]
}

# Maps to checks/root_mfa_status.py
resource "aws_config_config_rule" "root_mfa" {
  name = "cspm-root-account-mfa-enabled"
  source {
    owner             = "AWS"
    source_identifier = "ROOT_ACCOUNT_MFA_ENABLED"
  }
  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "root_no_access_key" {
  name = "cspm-iam-root-access-key-check"
  source {
    owner             = "AWS"
    source_identifier = "IAM_ROOT_ACCESS_KEY_CHECK"
  }
  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "iam_user_mfa" {
  name = "cspm-iam-user-mfa-enabled"
  source {
    owner             = "AWS"
    source_identifier = "IAM_USER_MFA_ENABLED"
  }
  depends_on = [aws_config_configuration_recorder.recorder]
}

# Maps to checks/logging_enabled.py
resource "aws_config_config_rule" "cloudtrail_enabled" {
  name = "cspm-cloudtrail-enabled"
  source {
    owner             = "AWS"
    source_identifier = "CLOUD_TRAIL_ENABLED"
  }
  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "vpc_flow_logs" {
  name = "cspm-vpc-flow-logs-enabled"
  source {
    owner             = "AWS"
    source_identifier = "VPC_FLOW_LOGS_ENABLED"
  }
  depends_on = [aws_config_configuration_recorder.recorder]
}

# Maps to checks/key_rotation_status.py
resource "aws_config_config_rule" "access_keys_rotated" {
  name = "cspm-access-keys-rotated"
  source {
    owner             = "AWS"
    source_identifier = "ACCESS_KEYS_ROTATED"
  }
  input_parameters = jsonencode({ maxAccessKeyAge = "90" })
  depends_on        = [aws_config_configuration_recorder.recorder]
}

# Maps to checks/public_snapshots.py
resource "aws_config_config_rule" "ebs_snapshot_public" {
  name = "cspm-ebs-snapshot-public-restorable-check"
  source {
    owner             = "AWS"
    source_identifier = "EBS_SNAPSHOT_PUBLIC_RESTORABLE_CHECK"
  }
  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "rds_snapshot_public" {
  name = "cspm-rds-snapshot-public-prohibited"
  source {
    owner             = "AWS"
    source_identifier = "RDS_SNAPSHOTS_PUBLIC_PROHIBITED"
  }
  depends_on = [aws_config_configuration_recorder.recorder]
}

# Maps to checks/overprivileged_roles.py
resource "aws_config_config_rule" "iam_policy_no_statements_with_admin_access" {
  name = "cspm-iam-policy-no-statements-with-admin-access"
  source {
    owner             = "AWS"
    source_identifier = "IAM_POLICY_NO_STATEMENTS_WITH_ADMIN_ACCESS"
  }
  depends_on = [aws_config_configuration_recorder.recorder]
}
