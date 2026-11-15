# IAM Policy Guard

A GitHub Action that runs AWS IAM Access Analyzer against every Terraform IAM change in a pull request, then has an LLM explain the risk and suggest a least-privilege rewrite. Access Analyzer decides pass/fail; the LLM only advises.

![status](https://img.shields.io/badge/status-in%20development-yellow)

## Why this matters
Overly broad IAM policies are one of the most common root causes in cloud breaches, and they usually arrive through ordinary pull requests that reviewers skim. Static linters catch syntax and obvious wildcards, but not "this change quietly grants new access." Access Analyzer's custom policy checks answer that question with automated reasoning. The missing piece is explaining the finding in plain language at review time, which is where an LLM helps, as long as it can't overrule the deterministic check.

## Demo
_TODO: screenshot of the PR comment on a PR that widens `examples/demo/main.tf`._

## Architecture
See [docs/architecture.md](docs/architecture.md).

## How it works
1. A PR touches `*.tf`; the workflow runs on `pull_request` (never `pull_request_target`).
2. The job gets short-lived AWS credentials via GitHub OIDC. No access keys exist.
3. IAM policy documents are extracted statically (python-hcl2, no `terraform plan`) from the changed `.tf` files at the base and head commits: `data "aws_iam_policy_document"` blocks and inline policies written as a JSON heredoc or JSON string. Files under the exclude list (default `tests/fixtures/`) are skipped and listed in the report.
4. For each new or changed policy, Access Analyzer runs `ValidatePolicy`, `CheckNoNewAccess` (head vs base; skipped for brand-new policies) and `CheckAccessNotGranted` (deny list). Documents with a `Principal` (role trust policies) are checked as resource policies, and the deny-list check is skipped for them. Policies identical to base aren't re-checked.
5. The verdict comes from those results only, and it fails closed: a policy it can't read (`jsonencode`, `file()`, variables), any API error, or more than 20 changed policies is a FAIL. The job's exit code is the gate.
6. Claude gets the policy and findings as untrusted data and writes an advisory explanation and suggested rewrite. This section appears only when `ANTHROPIC_API_KEY` is set; the LLM call itself is not implemented yet.
7. The report is posted as a single PR comment that's updated on each run (`gh pr comment --edit-last --create-if-none`).

## Security design
- **OIDC role scoped to one repo + `pull_request` only**, exact-match `sub` claim, 1-hour sessions, region-locked.
- **Three permissions total**, all Access Analyzer policy checks; each documented in `infra/main.tf`.
- **LLM is advisory.** `verdict.py` cannot import the LLM module; a test enforces it.
- **Prompt injection assumed.** PR content is untrusted input to the model.
- **No `terraform apply` on PRs**, so the workflow can't change infrastructure.
- Secret scanning + push protection, Checkov, Gitleaks, Dependabot.

Full analysis: [docs/threat-model.md](docs/threat-model.md).

## Known limitations
- **Terraform references aren't resolved.** Extraction is static, so a policy built from variables, locals, `jsonencode()` or `file()` can't be read. Those policies fail closed, and the report asks for a literal `aws_iam_policy_document` block or a JSON heredoc.
- **`infra/` is excluded.** The guard's own bootstrap role is written with references (the OIDC provider ARN, variables), so it would always fail closed. The workflow passes `--exclude infra/`, and those files are listed as skipped in every report rather than silently ignored.

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
# 3. Open a PR that widens examples/demo/main.tf (e.g. add "iam:PassRole" on "*")

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
- **Rename detection** (`git diff -M`): a renamed `.tf` file currently looks like a brand-new policy, so it loses its baseline and skips `CheckNoNewAccess`. Pair old and new paths so renamed files keep their baseline.
- **Resolve Terraform references**: read policies from `terraform plan` JSON (`terraform show -json`), or substitute worst-case wildcards for unresolved values, so policies that use variables can be checked instead of failing closed.
- **Stricter baseline for brand-new policies**: a new policy has nothing to compare against, so today only `ValidatePolicy` and the deny list apply. Compare it against a minimal reference policy (or require an explicit approval label) instead.

v1 non-goals: resource policies (S3/KMS/SQS), SCPs, auto-fix commits, `terraform plan`-based extraction, multi-account.

## Skills demonstrated
AWS IAM, IAM Access Analyzer, least privilege, GitHub Actions, OIDC workload identity federation, Terraform, policy-as-code, shift-left security, LLM security, prompt injection mitigation, threat modeling (STRIDE), Python.
