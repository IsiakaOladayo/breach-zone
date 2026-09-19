# infra/posture-management/backend.tf
#
# Why this is required for a GitHub-driven deployment: without a remote
# backend, terraform.tfstate lives on whichever machine ran `apply` last —
# which doesn't work once "whichever machine" is a fresh, disposable
# GitHub Actions runner every single time. This backend puts state in S3
# (versioned, so you can recover a previous state) with a DynamoDB table
# for locking, so two workflow runs (or a workflow run + a local `terraform
# plan` someone kicks off by hand) can't corrupt state by writing at once.
#
# This bucket and table are bootstrapped ONCE, the same way the OIDC role
# is (see terraform/bootstrap/) — a backend can't configure itself, since
# Terraform needs the backend to exist before it can run at all. Create
# them with two plain AWS CLI calls (not Terraform, to avoid the
# chicken-and-egg problem) before the first CI run:
#
#   aws s3api create-bucket --bucket YOUR-UNIQUE-TFSTATE-BUCKET \
#     --region us-east-1
#   aws s3api put-bucket-versioning --bucket YOUR-UNIQUE-TFSTATE-BUCKET \
#     --versioning-configuration Status=Enabled
#   aws s3api put-public-access-block --bucket YOUR-UNIQUE-TFSTATE-BUCKET \
#     --public-access-block-configuration \
#     BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
#
#   aws dynamodb create-table \
#     --table-name cspm-terraform-locks \
#     --attribute-definitions AttributeName=LockID,AttributeType=S \
#     --key-schema AttributeName=LockID,KeyType=HASH \
#     --billing-mode PAY_PER_REQUEST

terraform {
  backend "s3" {
    bucket         = "YOUR-UNIQUE-TFSTATE-BUCKET"   # set to the bucket you created above
    key            = "cspm-stack/terraform.tfstate"
    region         = "us-east-1"
    dynamodb_table = "cspm-terraform-locks"
    encrypt        = true
  }
}
