# Synthetic example (base branch). Account 111122223333 is the AWS docs placeholder.
resource "aws_iam_policy" "app_reader" {
  name = "app-reader"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject"]
      Resource = "arn:aws:s3:::example-app-bucket/*"
    }]
  })
}
