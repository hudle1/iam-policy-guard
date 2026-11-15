"""Markdown report for the PR comment.

Policy IDs contain file paths chosen by the PR author, so every one is rendered as inline
code with backticks, pipes and newlines neutralized (no markdown/link injection).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .verdict import BLOCKING_FINDING_TYPES, PolicyCheckResults, Result, Verdict


@dataclass
class RunSummary:
    """Everything the report shows besides the verdict itself."""

    checks: list[PolicyCheckResults] = field(default_factory=list)
    resource_policies: set[str] = field(default_factory=set)
    unsupported: dict[str, str] = field(default_factory=dict)
    skipped_files: list[str] = field(default_factory=list)
    unchanged: list[str] = field(default_factory=list)
    explanations: dict[str, str] | None = None  # None = AI section omitted entirely


def code(text: str, in_table: bool = False) -> str:
    """Render untrusted text as inline code that can't break out of its context.

    Backticks would end the code span and newlines would end a heading or list item, so
    both are neutralized everywhere. A pipe only needs escaping inside a table cell; in a
    heading or list GitHub would show the backslash literally.
    """
    safe = text.replace("`", "'").replace("\r", " ").replace("\n", " ")
    if in_table:
        safe = safe.replace("|", "\\|")
    return f"`{safe}`"


def _validate_cell(c: PolicyCheckResults) -> str:
    if not c.validate_finding_types:
        return "PASS (no findings)"
    blocking = set(c.validate_finding_types) & BLOCKING_FINDING_TYPES
    label = "FAIL" if blocking else "PASS"
    return f"{label} ({', '.join(sorted(set(c.validate_finding_types)))})"


def _nna_cell(c: PolicyCheckResults) -> str:
    return "N/A (new policy, no baseline)" if c.no_new_access is None else c.no_new_access.value


def _ang_cell(c: PolicyCheckResults) -> str:
    if c.access_not_granted is None:
        return "Skipped (resource policy)"
    return c.access_not_granted.value


def _reason_line(reason: str, policy_ids: set[str]) -> str:
    """Reasons start with a policy ID (an attacker-chosen path); render that part as code."""
    for pid in policy_ids:
        prefix = f"{pid}: "
        if reason.startswith(prefix):
            return f"- {code(pid)}: {reason[len(prefix):]}"
    return f"- {reason}"  # run-level errors: our own text, no policy ID


def render(verdict: Verdict, run: RunSummary) -> str:
    passed = verdict.result is Result.PASS
    lines = [f"# IAM Policy Guard: {'✅ PASS' if passed else '❌ FAIL'}", ""]

    if verdict.reasons:
        policy_ids = {c.policy_id for c in run.checks} | set(run.unsupported)
        lines += ["**Why it failed**", ""]
        lines += [_reason_line(r, policy_ids) for r in verdict.reasons]
        lines.append("")

    # One sub-heading per policy and a narrow two-column table, so long policy IDs never
    # force the PR comment to scroll sideways.
    lines += ["## Results", ""]
    if run.checks:
        for c in run.checks:
            lines += [
                f"### {code(c.policy_id)}",
                "",
                "| Check | Result |",
                "| --- | --- |",
                f"| ValidatePolicy | {_validate_cell(c)} |",
                f"| CheckNoNewAccess | {_nna_cell(c)} |",
                f"| CheckAccessNotGranted | {_ang_cell(c)} |",
                "",
            ]
    else:
        lines += ["No changed IAM policies were checked.", ""]

    if run.unsupported:
        lines += [
            "## Unsupported policies",
            "",
            "These could not be read statically, so they were not checked. Each one fails the "
            'run: rewrite it as a `data "aws_iam_policy_document"` block or a JSON heredoc.',
            "",
        ]
        lines += [f"- {code(p)}: {why}" for p, why in sorted(run.unsupported.items())]
        lines.append("")

    if run.skipped_files:
        lines += ["## Skipped files (exclude list)", ""]
        lines += [f"- {code(f)}" for f in run.skipped_files]
        lines.append("")

    if run.unchanged:
        lines += ["## Unchanged policies (identical to base, not re-checked)", ""]
        lines += [f"- {code(p)}" for p in run.unchanged]
        lines.append("")

    if run.resource_policies:
        lines += [
            "## Notes",
            "",
            "- Resource policies (documents with `Principal`, e.g. role trust policies) were "
            "validated as `AWS::IAM::AssumeRolePolicyDocument`. CheckAccessNotGranted was "
            "skipped for them: the deny list targets identity permissions, and every trust "
            "policy grants `sts:AssumeRole` by design.",
            "",
        ]

    if run.explanations is not None:
        lines += ["## AI explanation (advisory only, does not affect the verdict)", ""]
        if run.explanations:
            for pid, text in run.explanations.items():
                lines += [f"**{code(pid)}**", "", text, ""]
        else:
            lines += ["_Not available yet._", ""]

    lines.append("_Verdict comes from AWS IAM Access Analyzer only._")
    return "\n".join(lines) + "\n"
