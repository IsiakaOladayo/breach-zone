output "config_bucket_name" {
  value       = aws_s3_bucket.config_bucket.id
  description = "S3 bucket receiving AWS Config delivery channel snapshots and history."
}

output "config_role_arn" {
  value       = aws_iam_role.config_role.arn
  description = "IAM role AWS Config assumes to record configuration and evaluate rules."
}

output "sns_topic_arn" {
  value       = aws_sns_topic.config_notifications.arn
  description = "SNS topic for AWS Config configuration-change notifications."
}

output "config_rule_names" {
  value = [
    aws_config_config_rule.s3_public_read.name,
    aws_config_config_rule.s3_public_write.name,
    aws_config_config_rule.s3_ssl_only.name,
    aws_config_config_rule.restricted_ssh.name,
    aws_config_config_rule.restricted_common_ports.name,
    aws_config_config_rule.ebs_encrypted.name,
    aws_config_config_rule.rds_encrypted.name,
    aws_config_config_rule.s3_encrypted.name,
    aws_config_config_rule.root_mfa.name,
    aws_config_config_rule.root_no_access_key.name,
    aws_config_config_rule.iam_user_mfa.name,
    aws_config_config_rule.cloudtrail_enabled.name,
    aws_config_config_rule.vpc_flow_logs.name,
    aws_config_config_rule.access_keys_rotated.name,
    aws_config_config_rule.ebs_snapshot_public.name,
    aws_config_config_rule.rds_snapshot_public.name,
    aws_config_config_rule.iam_policy_no_statements_with_admin_access.name,
  ]
  description = "All 17 AWS Config managed rule names deployed by this stack, for use in screenshots/evidence."
}
