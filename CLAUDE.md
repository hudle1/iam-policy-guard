# IAM Policy Guard

A GitHub Action that blocks risky IAM policy changes in Terraform pull requests. It extracts IAM
policy documents from the PR's base and head commits, runs AWS IAM Access Analyzer checks
(`ValidatePolicy`, `CheckNoNewAccess`, `CheckAccessNotGranted`), and computes a deterministic
PASS/FAIL verdict that becomes the job's exit code. An LLM (Claude) may add a plain-language
explanation to the PR report, but it is advisory only and never affects the verdict.

## Rules

- **LLM output is advisory.** `src/iam_policy_guard/verdict.py` must never import LLM code
  (`anthropic`, `explain`). `tests/test_verdict.py` enforces this; never weaken that test.
- **Synthetic data only.** Use the AWS documentation placeholder account `111122223333` in
  examples, fixtures and tests. Never use real account IDs, ARNs or credentials.
- **Never run `terraform apply`, `terraform destroy`, or any `aws` CLI command.**
- **Never edit `docs/design-decisions.md`.** The owner writes it by hand.
- **Tests must not hit the network.** Inject a fake Access Analyzer client.
- **Run ruff and pytest before calling anything done.** Both must pass.

> **Known gap:** the deny rules in `.claude/settings.json` cover the Bash tool only. On Windows,
> Claude Code also has a PowerShell tool, and the same commands (`terraform apply`,
> `terraform destroy`, `aws`, `curl` / `Invoke-WebRequest`) are not blocked there by settings.
> The exact PowerShell permission-rule syntax wasn't confirmed, so no rules were added. Until
> they are, the rules above are enforced by instruction only, in both shells.

## How to run tests

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m pytest -q
```
