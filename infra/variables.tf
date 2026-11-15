variable "region" {
  description = "Region the workflow calls Access Analyzer in. The role is locked to this region."
  type        = string
  default     = "us-east-1"
}

variable "aws_account_id" {
  description = "Sandbox account ID; Terraform refuses to run against any other account"
  type        = string
}

variable "aws_profile" {
  description = "Local AWS CLI profile used to apply (use an IAM Identity Center/SSO profile, not access keys)."
  type        = string
  default     = null
}

variable "github_owner" {
  description = "GitHub user or org that owns the repo."
  type        = string
}

variable "github_repo" {
  description = "Repository name (without owner)."
  type        = string
  default     = "iam-policy-guard"
}

variable "github_owner_id" {
  description = "Numeric GitHub owner ID. Public and immutable (survives renames); used in GitHub's immutable OIDC subject. Find it with: gh api repos/OWNER/REPO/actions/oidc/customization/sub (the number after the owner's @ in sub_claim_prefix)."
  type        = number
}

variable "github_repo_id" {
  description = "Numeric GitHub repository ID. Public and immutable (survives renames); used in GitHub's immutable OIDC subject. Find it with: gh api repos/OWNER/REPO/actions/oidc/customization/sub (the number after the repo's @ in sub_claim_prefix)."
  type        = number
}

variable "create_oidc_provider" {
  description = "Set false if the account already has the token.actions.githubusercontent.com provider (only one is allowed per account)."
  type        = bool
  default     = true
}

variable "role_name" {
  description = "Name of the role GitHub Actions assumes."
  type        = string
  default     = "iam-policy-guard-gha"
}

variable "budget_email" {
  description = "Email for the monthly budget alert. Set null to skip creating the budget."
  type        = string
  default     = null
}

variable "budget_limit_usd" {
  description = "Monthly budget limit in USD."
  type        = string
  default     = "10"
}
