# infra/posture-management/bootstrap/ — run this ONCE, locally, by hand
#
# Why this is separate from the main stack: GitHub Actions can't create the
# IAM role it needs in order to authenticate to AWS in the first place —
# that's a chicken-and-egg problem. So this small stack is applied manually,
# one time, from your own machine with your own (human) AWS credentials. It
# creates the trust relationship; everything AFTER this point (the actual
# AWS Config stack) is deployed by CI using that trust relationship, with
# zero static AWS keys anywhere in GitHub.
#
# Usage (once):
#   cd infra/posture-management/bootstrap
#   terraform init
#   terraform apply \
#     -var="github_org=YOUR_GITHUB_ORG_OR_USERNAME" \
#     -var="github_repo=cspm-stack"
#
# Copy the printed `deploy_role_arn` output into the GitHub repo variable
# AWS_DEPLOY_ROLE_ARN (see .github/workflows/*.yml) — that's the only thing
# CI needs to know.

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

variable "aws_region" {
  type    = string
  default = "us-east-1"
}

variable "github_org" {
  description = "Your GitHub org or username, e.g. 'my-github-username'."
  type        = string
}

variable "github_repo" {
  description = "The repo name this trust relationship is scoped to."
  type        = string
}

variable "allowed_branch" {
  description = "Branch allowed to assume the deploy role for terraform apply (plan runs from any branch/PR)."
  type        = string
  default     = "main"
}

data "aws_caller_identity" "current" {}

# GitHub's OIDC identity provider. AWS accounts can only have one of these —
# if your account already has it (from a prior project, e.g. Cloud Security
# Project 1's federation work), import it instead of creating a duplicate:
#   terraform import aws_iam_openid_connect_provider.github \
#     arn:aws:iam::<account-id>:oidc-provider/token.actions.githubusercontent.com
resource "aws_iam_openid_connect_provider" "github" {
  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  # GitHub's OIDC thumbprint. AWS validates the provider's TLS chain
  # independently of this value now, but the field is still required.
  thumbprint_list = ["6938fd4d98bab03faadb97b34396831e3780aea1"]
}

# The role CI assumes. Trust policy is scoped narrowly:
#   - only GitHub's OIDC provider can assume it
#   - only for the exact repo named in var.github_repo
#   - the `aud` claim must be "sts.amazonaws.com" (GitHub's default)
# This means a workflow in a DIFFERENT repo — even in the same org — cannot
# assume this role, and a fork of this repo cannot either, because the
# sub claim encodes the exact repo path.
resource "aws_iam_role" "github_actions_deploy" {
  name = "cspm-github-actions-deploy"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Federated = aws_iam_openid_connect_provider.github.arn }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
        }
        StringLike = {
          # Allows: any branch/PR (for plan) AND the allowed branch (for apply).
          # Tighten this further (e.g. drop the wildcard) if you want plan-only
          # access from PRs and a SEPARATE, more-privileged role for apply.
          "token.actions.githubusercontent.com:sub" = [
            "repo:${var.github_org}/${var.github_repo}:ref:refs/heads/${var.allowed_branch}",
            "repo:${var.github_org}/${var.github_repo}:pull_request",
          ]
        }
      }
    }]
  })

  tags = { Purpose = "github-actions-oidc-deploy" }
}

# Scoped to exactly what this stack needs to create/read — NOT
# AdministratorAccess. Expand only as new resource types are added to
# config_rules.tf, and prefer adding specific actions over widening to "*".
resource "aws_iam_role_policy" "deploy_permissions" {
  name = "cspm-deploy-permissions"
  role = aws_iam_role.github_actions_deploy.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ConfigAndSupportingResources"
        Effect = "Allow"
        Action = [
          "config:*",
          "s3:CreateBucket", "s3:PutBucketPolicy", "s3:PutBucketPublicAccessBlock",
          "s3:PutEncryptionConfiguration", "s3:GetBucket*", "s3:GetEncryptionConfiguration",
          "s3:PutBucketAcl", "s3:GetBucketAcl", "s3:ListBucket", "s3:DeleteBucket",
          "iam:CreateRole", "iam:DeleteRole", "iam:GetRole", "iam:PassRole",
          "iam:AttachRolePolicy", "iam:DetachRolePolicy",
          "iam:PutRolePolicy", "iam:DeleteRolePolicy", "iam:GetRolePolicy",
          "iam:ListAttachedRolePolicies", "iam:ListRolePolicies",
          "iam:TagRole", "iam:ListRoleTags",
          "sns:CreateTopic", "sns:DeleteTopic", "sns:GetTopicAttributes",
          "sns:SetTopicAttributes", "sns:TagResource",
          "sts:GetCallerIdentity",
        ]
        Resource = "*"
      }
    ]
  })
}

output "deploy_role_arn" {
  value       = aws_iam_role.github_actions_deploy.arn
  description = "Paste this into the GitHub repo variable AWS_DEPLOY_ROLE_ARN."
}

output "oidc_provider_arn" {
  value = aws_iam_openid_connect_provider.github.arn
}
