# Synthetic fixture: comments in every position python-hcl2 can attach them.
# All of these must be ignored, never treated as policy fields.
data "aws_iam_policy_document" "commented" {
  # comment between document fields
  version = "2012-10-17" # trailing comment on an attribute

  statement {
    # comment inside a statement
    sid    = "ReadBucket"
    effect = "Allow"
    actions = [
      # own-line comment inside a list
      "s3:GetObject", # trailing comment on a list element
      // slash comment inside a list
      "s3:ListBucket",
      /* block comment */ "s3:GetObjectTagging",
    ]
    resources = ["arn:aws:s3:::example-app-bucket/*"]

    condition {
      # comment inside a condition block
      test     = "StringEquals"
      variable = "aws:PrincipalAccount" # trailing comment in condition
      values = [
        "111122223333", # trailing comment in condition values
      ]
    }
  }

  /*
   * Multi-line block comment between statements.
   */
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      # comment inside a principals block
      type = "AWS" # trailing comment in principals
      identifiers = [
        # own-line comment inside identifiers
        "arn:aws:iam::111122223333:root",
      ]
    }
  }
}

resource "aws_iam_role_policy" "commented_heredoc" {
  # comment inside a resource block
  name   = "commented-heredoc"
  role   = "example-role"
  policy = <<EOF
{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": "*"}]}
EOF
}
