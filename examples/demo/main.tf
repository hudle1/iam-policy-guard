# Synthetic demo for IAM Policy Guard. Nothing here is deployed.
# Least-privilege baseline: read-only access to objects in one example bucket.
# To see a FAIL, open a PR that widens it (e.g. add "s3:*" or "iam:PassRole" on "*").

data "aws_iam_policy_document" "app" {
  statement {
    sid       = "ReadAppObjects"
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["arn:aws:s3:::example-app-bucket/*"]
  }

  # DEMO ONLY: intentionally risky. iam:PassRole on "*" lets the holder hand any role
  # to a service (e.g. launch an EC2 instance as an admin role): privilege escalation.
  statement {
    sid       = "RiskyPassRoleDemo"
    effect    = "Allow"
    actions   = ["iam:PassRole"]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "app_reader" {
  name        = "app-reader"
  description = "Read objects in example-app-bucket"
  policy      = data.aws_iam_policy_document.app.json
}
