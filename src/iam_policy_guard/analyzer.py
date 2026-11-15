"""Thin wrappers over the three Access Analyzer APIs the OIDC role is allowed to call.

Cost: ValidatePolicy is free; CheckNoNewAccess and CheckAccessNotGranted are $0.002/call.
"""

from __future__ import annotations

import json

import boto3

# Actions that should never appear in a PR without a human looking hard at it.
DENY_LIST_ACTIONS = [
    "iam:PassRole",
    "iam:CreateAccessKey",
    "iam:PutRolePolicy",
    "iam:AttachRolePolicy",
    "sts:AssumeRole",
    "kms:Decrypt",
    "s3:PutBucketPolicy",
]


def client(region: str = "us-east-1"):
    return boto3.client("accessanalyzer", region_name=region)


def validate_policy(aa, document: dict) -> list[str]:
    resp = aa.validate_policy(policyDocument=json.dumps(document), policyType="IDENTITY_POLICY")
    return [f["findingType"] for f in resp.get("findings", [])]


def check_no_new_access(aa, new: dict, existing: dict) -> str:
    resp = aa.check_no_new_access(
        newPolicyDocument=json.dumps(new),
        existingPolicyDocument=json.dumps(existing),
        policyType="IDENTITY_POLICY",
    )
    return resp["result"]


def check_access_not_granted(aa, document: dict) -> str:
    resp = aa.check_access_not_granted(
        policyDocument=json.dumps(document),
        access=[{"actions": DENY_LIST_ACTIONS}],
        policyType="IDENTITY_POLICY",
    )
    return resp["result"]
