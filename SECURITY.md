# Security Policy

This is a portfolio project, not a supported product.

## Reporting a vulnerability
Please use GitHub's private vulnerability reporting (Security tab > Report a vulnerability). Do not open a public issue.

## Scope notes
- The repo contains only synthetic data (`111122223333` is the AWS documentation placeholder account).
- The workflow never runs `terraform apply` and its AWS role can only call three Access Analyzer policy-check APIs.
- LLM output is advisory and never determines the check result.
