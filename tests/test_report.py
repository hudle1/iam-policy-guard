from iam_policy_guard.report import RunSummary, code, render
from iam_policy_guard.verdict import PolicyCheckResults, Result, decide


def test_code_neutralizes_backticks_and_newlines_everywhere():
    assert code("a`b\nc") == "`a'b c`"


def test_code_escapes_pipes_only_in_tables():
    assert code("a|b", in_table=True) == "`a\\|b`"
    assert code("a|b") == "`a|b`"  # headings/lists would show the backslash literally


def _failing_run(policy_id: str):
    checks = [PolicyCheckResults(policy_id, ("SECURITY_WARNING",), Result.FAIL, Result.FAIL)]
    return decide(checks), RunSummary(checks=checks)


def test_results_grouped_per_policy_with_narrow_table():
    verdict, run = _failing_run("examples/demo/main.tf::data.aws_iam_policy_document.app")
    report = render(verdict, run)

    assert "### `examples/demo/main.tf::data.aws_iam_policy_document.app`" in report
    assert "| Check | Result |" in report
    assert "| ValidatePolicy | FAIL (SECURITY_WARNING) |" in report
    assert "| CheckNoNewAccess | FAIL |" in report
    assert "| CheckAccessNotGranted | FAIL |" in report
    assert "| Policy |" not in report  # no wide three-column table


def test_reasons_render_policy_id_as_code():
    """A path is chosen by the PR author; in 'Why it failed' it must not become a link."""
    evil = "[click](https://evil.example)/main.tf::data.aws_iam_policy_document.x"
    verdict, run = _failing_run(evil)
    report = render(verdict, run)

    why = report.split("**Why it failed**", 1)[1].split("## Results", 1)[0]
    assert f"- `{evil}`: CheckNoNewAccess FAIL" in why
    assert "\n- [click](" not in why
    assert f"### `{evil}`" in report


def test_newline_in_policy_id_cannot_escape_heading():
    verdict, run = _failing_run("a.tf::x\n# Injected heading")
    report = render(verdict, run)

    assert "\n# Injected heading" not in report
    assert "### `a.tf::x # Injected heading`" in report
