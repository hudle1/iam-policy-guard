# Synthetic fixture.
resource "aws_iam_role_policy" "heredoc" {
  name   = "heredoc"
  role   = "example-role"
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {"Effect": "Allow", "Action": "s3:ListBucket", "Resource": "arn:aws:s3:::example-app-bucket"}
  ]
}
EOF
}

resource "aws_iam_user_policy" "indented" {
  name   = "indented"
  user   = "example-user"
  policy = <<-JSON
    {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": "*"}]}
  JSON
}

resource "aws_iam_group_policy" "json_string" {
  name   = "json-string"
  group  = "example-group"
  policy = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"sns:Publish\",\"Resource\":\"*\"}]}"
}
