# Architecture

```mermaid
flowchart LR
  dev[Developer PR<br/>*.tf change] --> gha[GitHub Actions<br/>pull_request]
  gha -- OIDC token<br/>sub=repo:OWNER/REPO:pull_request --> sts[AWS STS]
  sts -- 1h creds --> gha
  gha -- policy JSON --> aa[IAM Access Analyzer<br/>Validate / NoNewAccess / NotGranted]
  aa -- results --> v{verdict.py<br/>deterministic}
  v -- exit code --> check[PR status check]
  aa -- findings --> llm[Claude API<br/>advisory only]
  gha -- redacted policy<br/>as untrusted data --> llm
  llm -- explanation + rewrite --> comment[PR comment]
  v -- pass/fail --> comment
```

## Data flow
| Data | From | To | Notes |
| --- | --- | --- | --- |
| OIDC JWT | GitHub | AWS STS | Short-lived, audience `sts.amazonaws.com` |
| Policy JSON | PR head + base | Access Analyzer, Claude | Synthetic data only; redact IDs before LLM |
| Findings | Access Analyzer | verdict.py, Claude, PR comment | |
| Explanation | Claude | PR comment | Never parsed into a decision |

## Trust boundaries
1. GitHub runner ↔ AWS (OIDC)
2. GitHub runner ↔ Anthropic API
3. PR author ↔ everything (PR content is untrusted)
