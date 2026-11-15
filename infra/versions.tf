terraform {
  required_version = ">= 1.6"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0" # thumbprint_list is optional for the OIDC provider in 6.x
    }
  }

  # Local state on purpose for a personal sandbox. State contains your account ID
  # and ARNs, so it is gitignored. Move to S3 + DynamoDB/S3 lockfile for anything shared.
}

provider "aws" {
  region  = var.region
  profile = var.aws_profile

  default_tags {
    tags = {
      Project   = "iam-policy-guard"
      ManagedBy = "terraform"
    }
  }
}
