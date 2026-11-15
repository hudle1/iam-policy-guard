import ast
import pathlib

from iam_policy_guard.verdict import PolicyCheckResults, Result, decide


def test_clean_policy_passes():
    v = decide([PolicyCheckResults("p1", ("SUGGESTION",), Result.PASS, Result.PASS)])
    assert v.result is Result.PASS


def test_new_access_fails():
    v = decide([PolicyCheckResults("p1", (), Result.FAIL, Result.PASS)])
    assert v.result is Result.FAIL


def test_deny_listed_action_fails():
    v = decide([PolicyCheckResults("p1", (), None, Result.FAIL)])
    assert v.result is Result.FAIL


def test_security_warning_fails():
    v = decide([PolicyCheckResults("p1", ("SECURITY_WARNING",), Result.PASS, Result.PASS)])
    assert v.result is Result.FAIL


def test_unsupported_policy_fails_closed():
    v = decide([], unsupported={"main.tf::aws_iam_policy.x": "uses jsonencode"})
    assert v.result is Result.FAIL
    assert "aws_iam_policy_document" in v.reasons[0]


def test_run_errors_fail_closed():
    v = decide([], errors=["Access Analyzer call failed (Throttling)"])
    assert v.result is Result.FAIL


def test_skipped_access_check_does_not_fail():
    v = decide([PolicyCheckResults("trust", (), Result.PASS, None)])
    assert v.result is Result.PASS


def test_verdict_module_cannot_see_llm_output():
    """Security control: the decision path must not import the LLM module or SDK.

    If someone later wires model output into decide(), this test breaks.
    """
    src = pathlib.Path(__file__).parents[1] / "src" / "iam_policy_guard" / "verdict.py"
    tree = ast.parse(src.read_text())
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported |= {a.name for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)
    forbidden = {"anthropic", "iam_policy_guard.explain", "explain"}
    assert not (imported & forbidden), f"verdict.py imports {imported & forbidden}"
