"""CLI entry point: python -m iam_policy_guard --base SHA --head SHA --report report.md

Exit code 0 = PASS, 1 = FAIL. Exit code comes from verdict.decide() only.
"""

from __future__ import annotations

import argparse
import sys


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="iam_policy_guard")
    p.add_argument("--base", required=True)
    p.add_argument("--head", required=True)
    p.add_argument("--report", default="report.md")
    p.parse_args(argv)
    # Saturday: extract -> analyzer -> verdict.decide -> explain -> write report
    raise NotImplementedError


if __name__ == "__main__":
    sys.exit(main())
