# Synthetic example (PR branch): broadens S3 and adds PassRole on *. Should FAIL.
resource "aws_iam_policy" "app_reader" {
  name = "app-reader"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:*"]
        Resource = "*"
      },
      {
        Effect   = "Allow"
        Action   = ["iam:PassRole"]
        Resource = "*"
      }
    ]
  })
}
