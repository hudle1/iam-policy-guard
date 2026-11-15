output "role_arn" {
  description = "Set this as the repo Actions variable AWS_ROLE_ARN (Settings > Secrets and variables > Actions > Variables)."
  value       = aws_iam_role.gha.arn
}

output "oidc_subject" {
  description = "The only OIDC subject allowed to assume the role."
  value       = local.oidc_subject
}
