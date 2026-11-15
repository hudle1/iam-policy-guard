"""Pass/fail decision. Inputs are Access Analyzer results ONLY.

This module must never import or accept LLM output. That is the core security control:
a prompt-injected PR can change what the explanation says, but not whether the PR passes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Result(str, Enum):
    PASS = "PASS"  # noqa: S105 - enum value, not a password
    FAIL = "FAIL"


# ValidatePolicy finding types that block a merge. SUGGESTION and WARNING are reported only.
BLOCKING_FINDING_TYPES = frozenset({"ERROR", "SECURITY_WARNING"})


@dataclass(frozen=True)
class PolicyCheckResults:
    """Raw results for one policy, as returned by Access Analyzer."""

    policy_id: str
    validate_finding_types: tuple[str, ...] = ()
    no_new_access: Result | None = None  # None = new policy, no base to compare
    access_not_granted: Result = Result.PASS


@dataclass
class Verdict:
    result: Result
    reasons: list[str] = field(default_factory=list)


def decide(checks: list[PolicyCheckResults]) -> Verdict:
    reasons: list[str] = []
    for c in checks:
        blocking = sorted(set(c.validate_finding_types) & BLOCKING_FINDING_TYPES)
        if blocking:
            reasons.append(f"{c.policy_id}: ValidatePolicy {', '.join(blocking)}")
        if c.no_new_access is Result.FAIL:
            reasons.append(f"{c.policy_id}: CheckNoNewAccess FAIL (grants new access)")
        if c.access_not_granted is Result.FAIL:
            reasons.append(f"{c.policy_id}: CheckAccessNotGranted FAIL (deny-listed action)")
    return Verdict(Result.FAIL if reasons else Result.PASS, reasons)
