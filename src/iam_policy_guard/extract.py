"""Find IAM policy documents in Terraform at a given git ref.

Saturday build. Open design question (write the answer in docs/design-decisions.md):
parse HCL statically (python-hcl2: jsonencode(...) and aws_iam_policy_document blocks)
vs. `terraform plan -out` + `terraform show -json`. Static parsing needs no AWS creds or
provider init and keeps the job near $0; plan JSON resolves variables and modules.
"""

from __future__ import annotations


def extract_policies(repo_root: str, ref: str) -> dict[str, dict]:
    """Return {policy_id: policy_document} for every IAM policy at `ref`."""
    raise NotImplementedError
