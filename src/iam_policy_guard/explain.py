"""Advisory LLM explanation + least-privilege suggestion. Saturday build.

Rules:
- Output is text for humans. It is never parsed into a decision.
- Policy JSON from the PR is untrusted: wrap it in delimiters, tell the model to treat it
  as data, and cap its length.
- Redact account IDs / ARNs before sending (synthetic data only in this repo anyway).
- On any API error, return a short "explanation unavailable" note; never fail the job.
"""

from __future__ import annotations


def explain(policy_id: str, document: dict, findings: list[str]) -> str:
    raise NotImplementedError
