"""CLI entry point: python -m iam_policy_guard --base SHA --head SHA --report report.md

Exit code 0 = PASS, 1 = FAIL. The exit code comes from verdict.decide() only; the LLM
explanation (if any) is generated afterwards and never feeds back into the decision.
"""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Callable

from . import analyzer
from .explain import explain
from .extract import changed_tf_files, extract_policies
from .report import RunSummary, render
from .verdict import PolicyCheckResults, Result, Verdict, decide

MAX_POLICIES = 20  # cost and blast-radius cap: more than this fails closed
DEFAULT_EXCLUDES = ("tests/fixtures/",)


def _error_label(exc: Exception) -> str:
    """Error code only. AWS error messages can contain the role ARN (and account ID), and
    the report is posted publicly, so the message text is deliberately not included."""
    resp = getattr(exc, "response", None)
    code = resp.get("Error", {}).get("Code") if isinstance(resp, dict) else None
    return code or type(exc).__name__


def _result(value: str) -> Result:
    return Result(value)  # raises ValueError on anything but PASS/FAIL -> treated as an error


def run(
    base: str,
    head: str,
    report_path: str,
    repo_root: str = ".",
    excludes: tuple[str, ...] = DEFAULT_EXCLUDES,
    client_factory: Callable[[], object] = analyzer.client,
) -> int:
    summary = RunSummary()
    errors: list[str] = []
    checks: list[PolicyCheckResults] = []

    try:
        changed = changed_tf_files(base, head, repo_root)
        summary.skipped_files = [f for f in changed if f.startswith(excludes)]
        paths = [f for f in changed if not f.startswith(excludes)]
        at_base = extract_policies(repo_root, base, paths)
        at_head = extract_policies(repo_root, head, paths)
    except Exception as e:  # noqa: BLE001 - any git failure fails closed with a message
        errors.append(f"Could not read the PR's Terraform files ({_error_label(e)})")
        at_base = at_head = None

    if at_head is not None:
        summary.unsupported = dict(at_head.unsupported)
        to_check = {}
        for pid, doc in at_head.policies.items():
            if at_base.policies.get(pid) == doc:
                summary.unchanged.append(pid)
            else:
                to_check[pid] = doc

        if len(to_check) > MAX_POLICIES:
            errors.append(
                f"{len(to_check)} changed policies exceeds the limit of {MAX_POLICIES}; "
                "split the PR into smaller changes"
            )
        elif to_check:
            try:
                aa = client_factory()
                for pid, doc in to_check.items():
                    resource = analyzer.is_resource_policy(doc)
                    if resource:
                        summary.resource_policies.add(pid)
                    baseline = at_base.policies.get(pid)
                    checks.append(
                        PolicyCheckResults(
                            policy_id=pid,
                            validate_finding_types=tuple(
                                analyzer.validate_policy(aa, doc, resource)
                            ),
                            no_new_access=None
                            if baseline is None
                            else _result(analyzer.check_no_new_access(aa, doc, baseline, resource)),
                            access_not_granted=None
                            if resource
                            else _result(analyzer.check_access_not_granted(aa, doc)),
                        )
                    )
            except Exception as e:  # noqa: BLE001 - any API failure fails closed
                errors.append(f"Access Analyzer call failed ({_error_label(e)}); failing closed")

    summary.checks = checks
    verdict: Verdict = decide(checks, summary.unsupported, errors)

    # Advisory only, after the verdict is final. Omitted entirely without an API key.
    if os.environ.get("ANTHROPIC_API_KEY"):
        summary.explanations = {}
        for c in checks:
            own = [r for r in verdict.reasons if r.startswith(f"{c.policy_id}: ")]
            if own:
                text = explain(c.policy_id, at_head.policies[c.policy_id], own)
                if text:
                    summary.explanations[c.policy_id] = text

    with open(report_path, "w", encoding="utf-8") as f:
        f.write(render(verdict, summary))
    return 0 if verdict.result is Result.PASS else 1


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="iam_policy_guard")
    p.add_argument("--base", required=True)
    p.add_argument("--head", required=True)
    p.add_argument("--report", default="report.md")
    p.add_argument("--repo-root", default=".")
    p.add_argument("--region", default="us-east-1")
    p.add_argument(
        "--exclude",
        action="append",
        help="path prefix to skip (repeatable; default: tests/fixtures/). Skipped files "
        "are listed in the report.",
    )
    a = p.parse_args(argv)
    excludes = tuple(a.exclude) if a.exclude else DEFAULT_EXCLUDES
    return run(
        a.base,
        a.head,
        a.report,
        a.repo_root,
        excludes,
        client_factory=lambda: analyzer.client(a.region),
    )


if __name__ == "__main__":
    sys.exit(main())
