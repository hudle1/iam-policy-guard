# Design decisions

## 1. Why Access Analyzer decides pass/fail, not the AI
Access Analyzer decides pass/fail because it uses math-based reasoning: give it the same policy and you always get the same answer. An AI isn’t guaranteed to give the same result each time, and it reads the PR’s text, so someone could use prompt injection, hiding instructions in the PR, to get a risky change approved. So in my design, the AI can only explain findings. The decision code can’t even load the AI code, and a test fails if anyone tries to connect them.

## 2. Why fail closed
Fail closed is safer than fail open. If a badge reader on a locked door fails, I’d want the door to stay locked, not swing open. My tool works the same way: if it can’t check a policy (a format it can’t read, an AWS error, too many policies, or a PR from a fork with no credentials), it blocks the PR until a human reviews it. If it failed open, an attacker could just write a risky policy in a format the tool can’t read and walk it straight past the gate. The trade-off is that it sometimes blocks a harmless change, but the message tells the author how to fix it. This proved itself during the build: a bug with comments in policy files made the tool block a change instead of quietly approving it.

## 3. Why static parsing, and its limits
I read the Terraform files directly as text to pull out policies. It’s simple, cheap, and needs no extra AWS access. The trade-off: it can’t see values filled in from elsewhere (references), so those policies are blocked, not guessed, and my infra/ folder is excluded and listed in the report. Next step: use terraform plan output to fill in those values.

## 4. Identity design: no long-lived keys anywhere
Nothing in this project uses long-lived keys. GitHub signs in to AWS with OIDC: each run gets a short-lived signed ID, swapped for credentials that expire within an hour and can only run three checks in one Region. The trust policy uses GitHub’s immutable repo IDs, so a recreated repo with the same name can’t take over the role. Terraform is pinned to my sandbox account with allowed_account_ids. I sign in through SSO with MFA, and root is locked away with two MFA devices.

## 5. Making it a real gate
A check that only reports isn’t a gate, so a ruleset on main blocks merging unless all five checks pass, with no bypass, even for me. Each required check is pinned to the GitHub Actions app, so nothing else can post a fake passing status. Strict mode makes PRs update to the latest main first, so the new-access comparison is never against a stale baseline. And because GitHub counts skipped checks as passing, fork PRs fail instead of skipping.

## 6. Building with an AI agent safely
Claude Code wrote most of the code. I reviewed every change before it was committed and made the design calls (fail closed, strict mode, keeping AI out of the verdict). The key safety control was credentials: I stayed signed out of AWS while it worked, so it couldn’t touch my account even by mistake. The deny rules in its settings were a backup layer. It also caught real issues for me, like a gitignore gap that could have committed a file with my account ID, and a way to spoof passing status checks.

## 7. What I'd do differently / next
Next, I’d add the AI explanation (v1.1), with prompt-injection defenses, since it reads untrusted PR content. I’d also add rename detection so moved files keep their comparison baseline, and pin GitHub Actions to exact versions (commit SHAs).

## Interview questions this answers
- "How would someone bypass your control?" (see 2 and 5)
- "Why not let the AI decide?" (see 1)
- "How does your CI access AWS without keys?" (see 4)
- "How did you use AI coding tools safely?" (see 6)