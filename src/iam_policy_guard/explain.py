"""Advisory LLM explanation + least-privilege suggestion. Not implemented yet (returns None).

Rules for the implementation:
- Output is text for humans. It is never parsed into a decision, and verdict.py never
  imports this module (tests/test_verdict.py enforces that).
- Policy JSON from the PR is untrusted: wrap it in delimiters, tell the model to treat it
  as data, and cap its length.
- Redact account IDs / ARNs before sending (synthetic data only in this repo anyway).
- On any API error, return None; never fail the job.
"""

from __future__ import annotations


def explain(policy_id: str, document: dict, findings: list[str]) -> str | None:
    """Return a plain-language explanation, or None if unavailable. LLM call: TODO."""
    return None
