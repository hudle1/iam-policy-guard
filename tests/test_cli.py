"""End-to-end CLI tests with a fake Access Analyzer client (no network, no AWS account)."""

import json

import pytest
from botocore.exceptions import ClientError, NoCredentialsError

from iam_policy_guard.__main__ import MAX_POLICIES, run
from iam_policy_guard.analyzer import DENY_LIST_ACTIONS, TRUST_POLICY_RESOURCE_TYPE


def _flatten(doc: dict, key: str) -> set[str]:
    out: set[str] = set()
    for s in doc["Statement"]:
        v = s.get(key, [])
        out |= {v} if isinstance(v, str) else set(v)
    return out


class FakeAA:
    """Crude stand-in with the same method names and response shapes as boto3."""

    def __init__(self):
        self.calls: list[tuple[str, dict]] = []

    def validate_policy(self, **kw):
        self.calls.append(("validate_policy", kw))
        doc = json.loads(kw["policyDocument"])
        risky = "iam:PassRole" in _flatten(doc, "Action") and "*" in _flatten(doc, "Resource")
        return {"findings": [{"findingType": "SECURITY_WARNING"}] if risky else []}

    def check_no_new_access(self, **kw):
        self.calls.append(("check_no_new_access", kw))
        new, old = json.loads(kw["newPolicyDocument"]), json.loads(kw["existingPolicyDocument"])
        grows = any(_flatten(new, k) - _flatten(old, k) for k in ("Action", "Resource"))
        if "Principal" in json.dumps(new):
            grows = grows or json.dumps(new) != json.dumps(old)
        return {"result": "FAIL" if grows else "PASS"}

    def check_access_not_granted(self, **kw):
        self.calls.append(("check_access_not_granted", kw))
        actions = _flatten(json.loads(kw["policyDocument"]), "Action")
        bad = actions & set(DENY_LIST_ACTIONS) or {a for a in actions if a.endswith("*")}
        return {"result": "FAIL" if bad else "PASS"}

    def called(self, name: str) -> list[dict]:
        return [kw for n, kw in self.calls if n == name]


def doc_tf(name: str, actions: list[str], resources: list[str]) -> str:
    return (
        f'data "aws_iam_policy_document" "{name}" {{\n'
        f"  statement {{\n"
        f"    actions   = {json.dumps(actions)}\n"
        f"    resources = {json.dumps(resources)}\n"
        f"  }}\n"
        f"}}\n"
    )


BUCKET = ["arn:aws:s3:::example-app-bucket/*"]


@pytest.fixture(autouse=True)
def no_api_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)


@pytest.fixture
def guard(gitrepo, tmp_path_factory):
    """Run the CLI between two commits; returns (exit_code, report_text, fake_client)."""
    report = tmp_path_factory.mktemp("out") / "report.md"

    def _run(base, head, fake=None, **kw):
        fake = fake or FakeAA()
        factory = kw.pop("client_factory", lambda: fake)
        code = run(base, head, str(report), str(gitrepo.path), client_factory=factory, **kw)
        return code, report.read_text(encoding="utf-8"), fake

    return _run


def test_clean_new_policy_passes(gitrepo, guard):
    base = gitrepo.commit({}, "empty")
    head = gitrepo.commit({"demo/main.tf": doc_tf("app", ["s3:GetObject"], BUCKET)})
    code, report, fake = guard(base, head)

    assert code == 0
    assert report.startswith("# IAM Policy Guard: ✅ PASS")
    assert "| CheckNoNewAccess | N/A (new policy, no baseline) |" in report
    assert fake.called("check_no_new_access") == []  # no baseline -> not called
    assert "AI explanation" not in report  # omitted entirely without ANTHROPIC_API_KEY


def test_narrowing_change_passes(gitrepo, guard):
    base = gitrepo.commit({"main.tf": doc_tf("app", ["s3:GetObject", "s3:PutObject"], BUCKET)})
    head = gitrepo.commit({"main.tf": doc_tf("app", ["s3:GetObject"], BUCKET)})
    code, report, fake = guard(base, head)

    assert code == 0
    assert len(fake.called("check_no_new_access")) == 1


def test_wildcard_and_passrole_fails(gitrepo, guard):
    base = gitrepo.commit({"main.tf": doc_tf("app", ["s3:GetObject"], BUCKET)})
    head = gitrepo.commit({"main.tf": doc_tf("app", ["s3:*", "iam:PassRole"], ["*"])})
    code, report, _ = guard(base, head)

    assert code == 1
    assert report.startswith("# IAM Policy Guard: ❌ FAIL")
    assert "CheckNoNewAccess FAIL" in report
    assert "CheckAccessNotGranted FAIL" in report
    assert "ValidatePolicy SECURITY_WARNING" in report


def test_api_error_fails_closed_without_leaking_arn(gitrepo, guard):
    class Denied(FakeAA):
        def validate_policy(self, **kw):
            raise ClientError(
                {
                    "Error": {
                        "Code": "AccessDeniedException",
                        "Message": "User: arn:aws:sts::111122223333:assumed-role/x is not "
                        "authorized to perform: access-analyzer:ValidatePolicy",
                    }
                },
                "ValidatePolicy",
            )

    base = gitrepo.commit({}, "empty")
    head = gitrepo.commit({"main.tf": doc_tf("app", ["s3:GetObject"], BUCKET)})
    code, report, _ = guard(base, head, fake=Denied())

    assert code == 1
    assert "Access Analyzer call failed (AccessDeniedException)" in report
    assert "arn:aws:sts" not in report and "111122223333" not in report


def test_missing_credentials_fails_closed(gitrepo, guard):
    def no_creds():
        raise NoCredentialsError()

    base = gitrepo.commit({}, "empty")
    head = gitrepo.commit({"main.tf": doc_tf("app", ["s3:GetObject"], BUCKET)})
    code, report, _ = guard(base, head, client_factory=no_creds)

    assert code == 1
    assert "NoCredentialsError" in report


def test_bad_ref_fails_closed(gitrepo, guard):
    head = gitrepo.commit({"main.tf": doc_tf("app", ["s3:GetObject"], BUCKET)})
    code, report, _ = guard("0" * 40, head)

    assert code == 1
    assert "Could not read the PR's Terraform files" in report


def test_more_than_limit_fails_without_api_calls(gitrepo, guard):
    many = "".join(doc_tf(f"p{i}", ["s3:GetObject"], BUCKET) for i in range(MAX_POLICIES + 1))
    base = gitrepo.commit({}, "empty")
    head = gitrepo.commit({"main.tf": many})

    def must_not_be_called():
        raise AssertionError("Access Analyzer must not be called over the limit")

    code, report, _ = guard(base, head, client_factory=must_not_be_called)

    assert code == 1
    assert f"{MAX_POLICIES + 1} changed policies exceeds the limit of {MAX_POLICIES}" in report


def test_unsupported_policy_fails_and_is_listed(gitrepo, guard):
    base = gitrepo.commit({}, "empty")
    head = gitrepo.commit({"main.tf": gitrepo.fixture("unsupported.tf")})
    code, report, _ = guard(base, head)

    assert code == 1
    assert "## Unsupported policies" in report
    assert "`main.tf::aws_iam_policy.encoded`" in report
    assert 'rewrite it as a data "aws_iam_policy_document" block or a JSON heredoc' in report


def test_excluded_fixture_is_listed_not_analyzed(gitrepo, guard):
    base = gitrepo.commit({}, "empty")
    # data_block.tf grants sts:AssumeRole; analyzed, it would be checked. Excluded, it's listed.
    head = gitrepo.commit({"tests/fixtures/data_block.tf": gitrepo.fixture("data_block.tf")})
    code, report, fake = guard(base, head)

    assert code == 0
    assert "## Skipped files (exclude list)" in report
    assert "- `tests/fixtures/data_block.tf`" in report
    assert fake.calls == []


def test_exclude_list_is_narrow(gitrepo, guard):
    base = gitrepo.commit({}, "empty")
    head = gitrepo.commit({"tests/other/main.tf": doc_tf("app", ["iam:PassRole"], ["*"])})
    code, report, _ = guard(base, head)

    assert code == 1  # only tests/fixtures/ is excluded by default, not all of tests/
    assert "Skipped files" not in report


def test_trust_policy_checked_as_resource_policy(gitrepo, guard):
    base = gitrepo.commit({"infra/main.tf": gitrepo.fixture("data_block.tf")})
    head_tf = gitrepo.fixture("data_block.tf").replace(
        '"arn:aws:iam::111122223333:root"',
        '"arn:aws:iam::111122223333:root", "arn:aws:iam::111122223333:role/extra"',
    )
    head = gitrepo.commit({"infra/main.tf": head_tf})
    code, report, fake = guard(base, head)

    trust_id = "infra/main.tf::data.aws_iam_policy_document.trust"
    (validate,) = fake.called("validate_policy")  # only the changed (trust) doc is checked
    assert validate["policyType"] == "RESOURCE_POLICY"
    assert validate["validatePolicyResourceType"] == TRUST_POLICY_RESOURCE_TYPE
    (nna,) = fake.called("check_no_new_access")
    assert nna["policyType"] == "RESOURCE_POLICY"
    assert fake.called("check_access_not_granted") == []

    assert code == 1  # new principal added -> CheckNoNewAccess FAIL
    assert f"| `{trust_id}` | CheckAccessNotGranted | Skipped (resource policy) |" in report
    assert "CheckAccessNotGranted was skipped for them" in report
    assert "`infra/main.tf::data.aws_iam_policy_document.app`" in report  # listed unchanged


def test_ai_section_only_when_key_set(gitrepo, guard, monkeypatch):
    base = gitrepo.commit({"main.tf": doc_tf("app", ["s3:GetObject"], BUCKET)})
    head = gitrepo.commit({"main.tf": doc_tf("app", ["iam:PassRole"], ["*"])})

    _, without_key, _ = guard(base, head)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-not-a-real-key")
    _, with_key, _ = guard(base, head)

    assert "AI explanation" not in without_key
    assert "## AI explanation (advisory only" in with_key
