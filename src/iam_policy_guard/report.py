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


def code(text: str) -> str:
    safe = text.replace("`", "'").replace("|", "\\|").replace("\r", " ").replace("\n", " ")
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


def render(verdict: Verdict, run: RunSummary) -> str:
    passed = verdict.result is Result.PASS
    lines = [f"# IAM Policy Guard: {'✅ PASS' if passed else '❌ FAIL'}", ""]

    if verdict.reasons:
        lines += ["**Why it failed**", ""]
        lines += [f"- {r}" for r in verdict.reasons]
        lines.append("")

    lines += ["## Results", ""]
    if run.checks:
        lines += ["| Policy | Check | Result |", "| --- | --- | --- |"]
        for c in run.checks:
            pid = code(c.policy_id)
            lines.append(f"| {pid} | ValidatePolicy | {_validate_cell(c)} |")
            lines.append(f"| {pid} | CheckNoNewAccess | {_nna_cell(c)} |")
            lines.append(f"| {pid} | CheckAccessNotGranted | {_ang_cell(c)} |")
    else:
        lines.append("No changed IAM policies were checked.")
    lines.append("")

    if run.unsupported:
        lines += [
            "## Unsupported policies",
            "",
            "These could not be read statically, so they were not checked. Each one fails the "
            'run: rewrite it as a `data "aws_iam_policy_document"` block or a JSON heredoc.',
            "",
            "| Policy | Reason |",
            "| --- | --- |",
        ]
        lines += [f"| {code(p)} | {why} |" for p, why in sorted(run.unsupported.items())]
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
