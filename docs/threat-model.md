# Threat model (draft — review and adjust)

Assets: AWS sandbox account, Anthropic API key, integrity of the PR status check.

| STRIDE | Threat | Mitigation |
| --- | --- | --- |
| Spoofing | Another repo, branch or fork assumes the AWS role | Exact-match `sub` = `repo:OWNER/REPO:pull_request`, `aud` check; forks get no OIDC token |
| Tampering | PR edits the workflow to call other AWS APIs | Role only allows 3 Access Analyzer actions in one region; branch protection requires review |
| Tampering | Prompt injection in policy text/comments flips the result | Verdict comes from Access Analyzer only; `verdict.py` cannot import LLM code (tested) |
| Repudiation | Unclear who triggered a check | CloudTrail logs `AssumeRoleWithWebIdentity` with session name `policy-guard-pr-<n>` |
| Info disclosure | API key exfiltrated by a malicious PR | `pull_request` not `pull_request_target`; fork PRs skipped; same-repo PRs require write access |
| Info disclosure | Real account IDs/ARNs sent to the LLM | Synthetic data only; redaction before the API call |
| DoS / cost | PR spam drives up paid checks or LLM tokens | Concurrency cancel, paths filter, $10 budget alarm, cap policies per run |
| Elevation | Workflow gains infra write access | No `terraform apply`; role has no IAM/write permissions |

Residual risk: a collaborator with write access can modify the workflow on a branch and use the role, but only for Access Analyzer checks. Production fix: require approval for workflow file changes (CODEOWNERS + rulesets) and use GitHub environments with required reviewers.
