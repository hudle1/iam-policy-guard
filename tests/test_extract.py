"""extract.py tests. Each test builds a throwaway git repo from tests/fixtures (no network)."""

import pathlib
import shutil
import subprocess

import pytest

from iam_policy_guard.extract import changed_tf_files, extract_policies

FIXTURES = pathlib.Path(__file__).parent / "fixtures"


def git(repo: pathlib.Path, *args: str) -> str:
    return subprocess.run(  # noqa: S603
        ["git", "-c", "user.name=test", "-c", "user.email=test@example.com", *args],  # noqa: S607
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def commit(repo: pathlib.Path, files: dict[str, str], message: str) -> str:
    """Copy fixtures into the repo (dest path -> fixture name) and commit. Returns the SHA."""
    for dest, fixture in files.items():
        target = repo / dest
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(FIXTURES / fixture, target)
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "--allow-empty", "-m", message)
    return git(repo, "rev-parse", "HEAD")


@pytest.fixture
def repo(tmp_path: pathlib.Path) -> pathlib.Path:
    git(tmp_path, "init", "-q")
    return tmp_path


def test_data_block_converted_to_iam_json(repo):
    sha = commit(repo, {"infra/main.tf": "data_block.tf"}, "data block")
    result = extract_policies(str(repo), sha, ["infra/main.tf"])

    assert result.policies["infra/main.tf::data.aws_iam_policy_document.app"] == {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "ReadBucket",
                "Effect": "Allow",
                "Action": ["s3:GetObject"],
                "Resource": ["arn:aws:s3:::example-app-bucket/*"],
                "Condition": {"StringEquals": {"aws:PrincipalAccount": ["111122223333"]}},
            },
            {
                "Effect": "Deny",
                "NotAction": ["s3:*"],
                "NotResource": ["arn:aws:s3:::example-app-bucket/*"],
            },
        ],
    }
    assert result.policies["infra/main.tf::data.aws_iam_policy_document.trust"] == {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["sts:AssumeRole"],
                "Principal": {"AWS": ["arn:aws:iam::111122223333:root"]},
            }
        ],
    }
    # The aws_iam_policy references the data doc in the same file: covered, not duplicated.
    assert "infra/main.tf::aws_iam_policy.app" not in result.policies
    assert result.unsupported == {}


def test_heredoc_and_json_string_policies(repo):
    sha = commit(repo, {"main.tf": "heredoc.tf"}, "heredoc")
    result = extract_policies(str(repo), sha, ["main.tf"])

    assert result.policies["main.tf::aws_iam_role_policy.heredoc"]["Statement"] == [
        {
            "Effect": "Allow",
            "Action": "s3:ListBucket",
            "Resource": "arn:aws:s3:::example-app-bucket",
        }
    ]
    assert (
        result.policies["main.tf::aws_iam_user_policy.indented"]["Statement"][0]["Action"]
        == "sqs:SendMessage"
    )
    assert (
        result.policies["main.tf::aws_iam_group_policy.json_string"]["Statement"][0]["Action"]
        == "sns:Publish"
    )
    assert result.unsupported == {}


def test_unsupported_forms_are_listed_not_crashing(repo):
    sha = commit(repo, {"main.tf": "unsupported.tf"}, "unsupported")
    result = extract_policies(str(repo), sha, ["main.tf"])

    assert result.policies == {}
    assert set(result.unsupported) == {
        "main.tf::aws_iam_policy.encoded",
        "main.tf::aws_iam_policy.from_file",
        "main.tf::aws_iam_policy.other_module_ref",
        "main.tf::data.aws_iam_policy_document.uses_variable",
        "main.tf::data.aws_iam_policy_document.dynamic_statements",
    }
    assert "expression" in result.unsupported["main.tf::aws_iam_policy.encoded"]


def test_unparseable_file_is_listed_not_crashing(repo):
    (repo / "broken.tf").write_text('resource "aws_iam_policy" "x" {\n  policy = \n')
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "broken")
    result = extract_policies(str(repo), "HEAD", ["broken.tf"])

    assert result.policies == {}
    assert result.unsupported == {"broken.tf::<file>": "could not parse HCL"}


def test_new_file_absent_at_base(repo):
    base = commit(repo, {}, "empty base")
    head = commit(repo, {"examples/demo/main.tf": "data_block.tf"}, "add policy")

    changed = changed_tf_files(base, head, repo_root=str(repo))
    assert changed == ["examples/demo/main.tf"]

    at_base = extract_policies(str(repo), base, changed)
    at_head = extract_policies(str(repo), head, changed)
    assert at_base.policies == {} and at_base.unsupported == {}
    assert "examples/demo/main.tf::data.aws_iam_policy_document.app" in at_head.policies


def test_changed_tf_files_ignores_non_tf(repo):
    base = commit(repo, {"a.tf": "heredoc.tf"}, "base")
    (repo / "README.md").write_text("docs change\n")
    head = commit(repo, {"nested/dir/b.tf": "data_block.tf"}, "head")

    assert changed_tf_files(base, head, repo_root=str(repo)) == ["nested/dir/b.tf"]


def test_bad_ref_raises_so_caller_can_fail_closed(repo):
    commit(repo, {"a.tf": "heredoc.tf"}, "base")
    with pytest.raises(RuntimeError):
        extract_policies(str(repo), "does-not-exist", ["a.tf"])
    with pytest.raises(ValueError):
        extract_policies(str(repo), "--output=/tmp/x", ["a.tf"])
