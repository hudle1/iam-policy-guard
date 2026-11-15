"""Thin wrappers over the three Access Analyzer APIs the OIDC role is allowed to call.

Cost: ValidatePolicy is free; CheckNoNewAccess and CheckAccessNotGranted are $0.002/call.

Policy types (confirmed against the botocore service model):
- ValidatePolicy: IDENTITY_POLICY or RESOURCE_POLICY (+ validatePolicyResourceType).
- CheckNoNewAccess / CheckAccessNotGranted: IDENTITY_POLICY or RESOURCE_POLICY.

A document with Principal/NotPrincipal is treated as a resource policy (in this repo's
scope, a role trust policy). CheckAccessNotGranted is NOT run on those: the deny list below
is about identity permissions, and every trust policy grants sts:AssumeRole by design, so
the check would fail all of them. The report says so.
"""

from __future__ import annotations

import json

DENY_LIST_ACTIONS = [
    "iam:PassRole",
    "iam:CreateAccessKey",
    "iam:PutRolePolicy",
    "iam:AttachRolePolicy",
    "sts:AssumeRole",
    "kms:Decrypt",
    "s3:PutBucketPolicy",
]

IDENTITY_POLICY = "IDENTITY_POLICY"
RESOURCE_POLICY = "RESOURCE_POLICY"
TRUST_POLICY_RESOURCE_TYPE = "AWS::IAM::AssumeRolePolicyDocument"


def client(region: str = "us-east-1"):
    import boto3  # imported lazily so tests and --help never need AWS libraries loaded

    return boto3.client("accessanalyzer", region_name=region)


def is_resource_policy(document: dict) -> bool:
    statements = document.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    return any(
        isinstance(s, dict) and ("Principal" in s or "NotPrincipal" in s) for s in statements
    )


def validate_policy(aa, document: dict, resource_policy: bool = False) -> list[str]:
    """Return the findingType of every ValidatePolicy finding (all pages)."""
    kwargs = {"policyDocument": json.dumps(document)}
    if resource_policy:
        kwargs["policyType"] = RESOURCE_POLICY
        kwargs["validatePolicyResourceType"] = TRUST_POLICY_RESOURCE_TYPE
    else:
        kwargs["policyType"] = IDENTITY_POLICY
    finding_types: list[str] = []
    while True:
        resp = aa.validate_policy(**kwargs)
        finding_types += [f["findingType"] for f in resp.get("findings", [])]
        token = resp.get("nextToken")
        if not token:
            return finding_types
        kwargs["nextToken"] = token


def check_no_new_access(aa, new: dict, existing: dict, resource_policy: bool = False) -> str:
    resp = aa.check_no_new_access(
        newPolicyDocument=json.dumps(new),
        existingPolicyDocument=json.dumps(existing),
        policyType=RESOURCE_POLICY if resource_policy else IDENTITY_POLICY,
    )
    return resp["result"]


def check_access_not_granted(aa, document: dict) -> str:
    """Identity policies only (see module docstring)."""
    resp = aa.check_access_not_granted(
        policyDocument=json.dumps(document),
        access=[{"actions": DENY_LIST_ACTIONS}],
        policyType=IDENTITY_POLICY,
    )
    return resp["result"]
