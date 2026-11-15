locals {
  oidc_host = "token.actions.githubusercontent.com"

  # Exact match: only workflows triggered by `pull_request` in this one repo.
  # Pushes, other branches' workflow_dispatch, other repos and forks cannot assume the role.
  # (Fork PRs never get an OIDC token under `pull_request` anyway.)
  oidc_subject = "repo:${var.github_owner}/${var.github_repo}:pull_request"

  oidc_provider_arn = var.create_oidc_provider ? aws_iam_openid_connect_provider.github[0].arn : data.aws_iam_openid_connect_provider.github[0].arn
}

# --- GitHub OIDC identity provider -------------------------------------------

resource "aws_iam_openid_connect_provider" "github" {
  count = var.create_oidc_provider ? 1 : 0

  url            = "https://${local.oidc_host}"
  client_id_list = ["sts.amazonaws.com"]
  # No thumbprint_list: AWS validates GitHub's cert against its trusted CA library.
}

data "aws_iam_openid_connect_provider" "github" {
  count = var.create_oidc_provider ? 0 : 1
  url   = "https://${local.oidc_host}"
}

# --- Role assumed by the PR workflow -----------------------------------------

data "aws_iam_policy_document" "trust" {
  statement {
    sid     = "GitHubActionsPullRequestOnly"
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [local.oidc_provider_arn]
    }

    condition {
      test     = "StringEquals"
      variable = "${local.oidc_host}:aud"
      values   = ["sts.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "${local.oidc_host}:sub"
      values   = [local.oidc_subject]
    }
  }
}

resource "aws_iam_role" "gha" {
  name                 = var.role_name
  path                 = "/github-actions/"
  description          = "Assumed by ${var.github_owner}/${var.github_repo} PR workflow. Access Analyzer policy checks only."
  assume_role_policy   = data.aws_iam_policy_document.trust.json
  max_session_duration = 3600
}

# Every permission, and why:
#   ValidatePolicy        - grammar + best-practice findings (free)
#   CheckNoNewAccess      - does the PR's policy grant anything the base branch didn't ($0.002/call)
#   CheckAccessNotGranted - does the policy grant any action on the deny list ($0.002/call)
# None of these support resource-level permissions, so Resource must be "*".
# The region condition stops the credentials being used anywhere else.
data "aws_iam_policy_document" "access_analyzer_checks" {
  statement {
    sid    = "AccessAnalyzerPolicyChecksOnly"
    effect = "Allow"
    actions = [
      "access-analyzer:ValidatePolicy",
      "access-analyzer:CheckNoNewAccess",
      "access-analyzer:CheckAccessNotGranted",
    ]
    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "aws:RequestedRegion"
      values   = [var.region]
    }
  }
}

resource "aws_iam_role_policy" "access_analyzer_checks" {
  name   = "access-analyzer-policy-checks"
  role   = aws_iam_role.gha.id
  policy = data.aws_iam_policy_document.access_analyzer_checks.json
}

# --- Cost guardrail ----------------------------------------------------------

resource "aws_budgets_budget" "monthly" {
  count = var.budget_email == null ? 0 : 1

  name         = "iam-policy-guard-monthly"
  budget_type  = "COST"
  limit_amount = var.budget_limit_usd
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 50
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_email_addresses = [var.budget_email]
  }

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 100
    threshold_type             = "PERCENTAGE"
    notification_type          = "FORECASTED"
    subscriber_email_addresses = [var.budget_email]
  }
}
