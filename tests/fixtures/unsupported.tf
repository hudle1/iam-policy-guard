# Synthetic fixture: forms static parsing can't resolve. Each must be listed, never crash.
variable "bucket" {
  type    = string
  default = "example-app-bucket"
}

resource "aws_iam_policy" "encoded" {
  name = "encoded"
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["s3:*"], Resource = "*" }]
  })
}

resource "aws_iam_policy" "from_file" {
  name   = "from-file"
  policy = file("${path.module}/policy.json")
}

resource "aws_iam_policy" "other_module_ref" {
  name   = "other-module-ref"
  policy = data.aws_iam_policy_document.not_in_this_file.json
}

data "aws_iam_policy_document" "uses_variable" {
  statement {
    actions   = ["s3:GetObject"]
    resources = ["arn:aws:s3:::${var.bucket}/*"]
  }
}

data "aws_iam_policy_document" "dynamic_statements" {
  dynamic "statement" {
    for_each = ["a"]
    content {
      actions   = ["s3:GetObject"]
      resources = ["*"]
    }
  }
}
