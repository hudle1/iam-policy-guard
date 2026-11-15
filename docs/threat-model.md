# Threat model (draft — review and adjust)

Assets: AWS sandbox account, Anthropic API key, integrity of the PR status check.

| STRIDE | Threat | Mitigation |
| --- | --- | --- |
| Spoofing | Another repo, branch or fork assumes the AWS role | Exact-match immutable `sub` = `repo:OWNER@OWNER_ID/REPO@REPO_ID:pull_request` (survives renames, blocks look-alike repos), `aud` check; forks get no OIDC token |
| Spoofing | Repo-name takeover: the repo or owner is renamed or deleted, and an attacker creates a new repo with the same name to assume the OIDC role | Trust policy matches the immutable subject with numeric owner and repo IDs, which GitHub never reuses; a same-name repo gets a different `sub` and is rejected |
| Spoofing | Spoofed status check: another GitHub App or a token with `statuses: write` posts a passing `guard` status | `main` ruleset pins every required check to the GitHub Actions app (`integration_id` 15368); statuses from any other source don't satisfy it |
| Elevation | Fork-PR bypass: the guard job is skipped for forks, and a skipped required check counts as passing, so an unchecked fork PR could merge | No job-level `if`; the first step fails fork PRs with an explicit message before checkout (fork code never runs); strict mode also requires re-checking against the latest `main` |
| Tampering | PR edits the workflow to call other AWS APIs | Role only allows 3 Access Analyzer actions in one region; `main` ruleset requires a PR and all five checks (0 approvals: single maintainer) |
| Tampering | Prompt injection in policy text/comments flips the result | Verdict comes from Access Analyzer only; `verdict.py` cannot import LLM code (tested) |
| Tampering (future, v1.1) | Prompt injection via PR content into the LLM explanation: crafted comments or policy text make the explanation lie, hide the real risk, or tell reviewers to approve | Explanation is advisory and generated after the verdict; never parsed into a decision; PR content delimited and labeled as untrusted data, length-capped, IDs redacted; report states the verdict comes from Access Analyzer only |
| Repudiation | Unclear who triggered a check | CloudTrail logs `AssumeRoleWithWebIdentity` with session name `policy-guard-pr-<n>` |
| Info disclosure | API key exfiltrated by a malicious PR | `pull_request` not `pull_request_target`; fork PRs fail the required `guard` check before checkout (no credentials, never run); same-repo PRs require write access |
| Info disclosure | Real account IDs/ARNs sent to the LLM | Synthetic data only; redaction before the API call |
| DoS / cost | PR spam drives up paid checks or LLM tokens | Concurrency cancel, unchanged policies not re-checked, $10 budget alarm, fail closed above 20 changed policies per run |
| Elevation | Workflow gains infra write access | No `terraform apply`; role has no IAM/write permissions |

Residual risk: a collaborator with write access can modify the workflow on a branch and use the role, but only for Access Analyzer checks. Production fix: require approval for workflow file changes (CODEOWNERS + rulesets) and use GitHub environments with required reviewers.
