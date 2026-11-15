# Synthetic fixture. Account 111122223333 is the AWS docs placeholder.
data "aws_iam_policy_document" "app" {
  statement {
    sid       = "ReadBucket"
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["arn:aws:s3:::example-app-bucket/*"]

    condition {
      test     = "StringEquals"
      variable = "aws:PrincipalAccount"
      values   = ["111122223333"]
    }
  }

  statement {
    effect        = "Deny"
    not_actions   = ["s3:*"]
    not_resources = ["arn:aws:s3:::example-app-bucket/*"]
  }
}

data "aws_iam_policy_document" "trust" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::111122223333:root"]
    }
  }
}

# Uses the data document above: already covered, so not reported separately.
resource "aws_iam_policy" "app" {
  name   = "app"
  policy = data.aws_iam_policy_document.app.json
}
