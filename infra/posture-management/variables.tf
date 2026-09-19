variable "aws_region" {
  description = "Region to deploy the AWS Config recorder, delivery channel, and managed rules into."
  type        = string
  default     = "us-east-1"
}

variable "config_bucket_name" {
  description = "Globally-unique S3 bucket name for AWS Config's delivery channel. Must not already exist."
  type        = string
}

variable "sns_topic_name" {
  description = "SNS topic AWS Config publishes configuration-change notifications to."
  type        = string
  default     = "cspm-config-notifications"
}

variable "environment_tag" {
  description = "Tag applied to all resources created by this stack, for easy identification/teardown."
  type        = string
  default     = "vaultcloud-phase3-cspm"
}
