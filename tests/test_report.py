from iam_policy_guard.report import code


def test_policy_ids_cannot_inject_markdown():
    assert code("a`b|c\nd") == "`a'b\\|c d`"
