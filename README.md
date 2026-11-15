# IAM Policy Guard

A GitHub Action that runs AWS IAM Access Analyzer against every Terraform IAM change in a pull request, then has an LLM explain the risk and suggest a least-privilege rewrite. Access Analyzer decides pass/fail; the LLM only advises.

![status](https://img.shields.io/badge/status-in%20development-yellow)

## Why this matters
Overly broad IAM policies are one of the most common root causes in cloud breaches, and they usually arrive through ordinary pull requests that reviewers skim. Static linters catch syntax and obvious wildcards, but not "this change quietly grants new access." Access Analyzer's custom policy checks answer that question with automated reasoning. The missing piece is explaining the finding in plain language at review time, which is where an LLM helps, as long as it can't overrule the deterministic check.

## Demo
_TODO (Sun): screenshot of the PR comment on `examples/risky-change`._

## Architecture
See [docs/architecture.md](docs/architecture.md).

## How it works
1. A PR touches `*.tf`; the workflow runs on `pull_request` (never `pull_request_target`).
2. The job gets short-lived AWS credentials via GitHub OIDC. No access keys exist.
3. IAM policy documents are extracted from the base and head commits.
4. Access Analyzer runs `ValidatePolicy`, `CheckNoNewAccess` (head vs base) and `CheckAccessNotGranted` (deny list).
5. The verdict is computed from those results only; the job's exit code is the gate.
6. Claude gets the policy and findings as untrusted data and writes an advisory explanation and suggested rewrite.
7. The report is posted as a single, updated PR comment.

## Security design
- **OIDC role scoped to one repo + `pull_request` only**, exact-match `sub` claim, 1-hour sessions, region-locked.
- **Three permissions total**, all Access Analyzer policy checks; each documented in `infra/main.tf`.
- **LLM is advisory.** `verdict.py` cannot import the LLM module; a test enforces it.
- **Prompt injection assumed.** PR content is untrusted input to the model.
- **No `terraform apply` on PRs**, so the workflow can't change infrastructure.
- Secret scanning + push protection, Checkov, Gitleaks, Dependabot.

Full analysis: [docs/threat-model.md](docs/threat-model.md).

## Quick start
New to AWS? Start with the full [setup guide](docs/setup-guide.md): account creation, root lockdown, SSO, and tools, with the pitfalls called out.

```bash
# 1. Deploy the OIDC role into a sandbox account (use an SSO profile, not access keys)
cd infra
cp terraform.tfvars.example terraform.tfvars   # edit values
terraform init && terraform apply
# 2. In GitHub: Settings > Secrets and variables > Actions
#    Secret   AWS_ROLE_ARN = <role_arn output>
#    Secret   ANTHROPIC_API_KEY
# 3. Open a PR that changes examples/risky-change/main.tf

# Teardown
terraform destroy
```

## Cost
- AWS: `ValidatePolicy` is free; `CheckNoNewAccess` and `CheckAccessNotGranted` are $0.002 per call. A PR changing 3 policies costs about $0.012. IAM roles and OIDC providers are free.
- Anthropic API: _TODO: record tokens/cost per run._
- Expected total for this project: well under $1/month.

## What I'd do in production
_TODO_

## Roadmap
v1 non-goals: resource policies (S3/KMS/SQS), SCPs, auto-fix commits, `terraform plan`-based extraction, multi-account.

## Skills demonstrated
AWS IAM, IAM Access Analyzer, least privilege, GitHub Actions, OIDC workload identity federation, Terraform, policy-as-code, shift-left security, LLM security, prompt injection mitigation, threat modeling (STRIDE), Python.
