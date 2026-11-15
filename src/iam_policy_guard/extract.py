"""Find IAM policy documents in Terraform files at a given git ref.

Static parsing with python-hcl2: no AWS credentials, no provider init, near $0 per run.

Supported:
- data "aws_iam_policy_document" blocks with literal values, converted to IAM JSON.
- aws_iam_policy / aws_iam_role_policy / aws_iam_user_policy / aws_iam_group_policy whose
  `policy` is a JSON heredoc or a JSON string literal.

Anything else (jsonencode(), file(), variables, dynamic blocks, ...) is recorded in
`Extraction.unsupported` with a reason, so the report can list it. This module never raises
on Terraform content; it only raises if git itself fails (bad ref, not a repo), so the
caller can fail closed.

Shape notes (python-hcl2 8.x, confirmed with a probe): block type/name keys and string
values keep their HCL double quotes, every block carries an `__is_block__` key, nested
blocks are lists of dicts, heredocs come back as '"<<EOF\\n...\\nEOF"', and expressions
come back as '${...}'. The helpers below also accept unquoted strings so a future hcl2
release that strips quotes keeps working.
"""

from __future__ import annotations

import json
import re
import subprocess  # noqa: S404 - git is called with fixed argv lists, never a shell
from dataclasses import dataclass, field

import hcl2

POLICY_DOC_DATA_TYPE = "aws_iam_policy_document"
INLINE_POLICY_RESOURCE_TYPES = frozenset(
    {"aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy", "aws_iam_group_policy"}
)

_BLOCK_MARKER = "__is_block__"
_DOC_KEYS = {"statement", "version", "policy_id", _BLOCK_MARKER}
_STATEMENT_KEYS = {
    "sid",
    "effect",
    "actions",
    "not_actions",
    "resources",
    "not_resources",
    "principals",
    "not_principals",
    "condition",
    _BLOCK_MARKER,
}
_LIST_FIELDS = {
    "actions": "Action",
    "not_actions": "NotAction",
    "resources": "Resource",
    "not_resources": "NotResource",
}
_HEREDOC_RE = re.compile(r"\A<<-?(\w+)\n(.*?)\n?[ \t]*\1\Z", re.DOTALL)
_DATA_DOC_REF_RE = re.compile(r"\A\$\{data\.aws_iam_policy_document\.([\w-]+)\.json\}\Z")


@dataclass
class Extraction:
    """Policies found at one git ref."""

    policies: dict[str, dict] = field(default_factory=dict)  # policy_id -> IAM JSON
    unsupported: dict[str, str] = field(default_factory=dict)  # policy_id -> reason


class _Unsupported(Exception):
    """Raised internally when a value can't be resolved statically."""


# --------------------------------------------------------------------------- git helpers


def _check_ref(ref: str) -> None:
    if not ref or ref.startswith("-"):
        raise ValueError(f"invalid git ref: {ref!r}")


def _git(repo_root: str, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed argv, no shell, refs validated
        ["git", *args],  # noqa: S607 - git is resolved from PATH on runners and dev machines
        cwd=repo_root,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )


def _verify_commit(repo_root: str, ref: str) -> None:
    """Raise if `ref` isn't a commit, so a typo can't silently mean 'no policies'."""
    _check_ref(ref)
    r = _git(repo_root, "rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}")
    if r.returncode != 0:
        raise RuntimeError(f"git ref not found: {ref}")


def changed_tf_files(base: str, head: str, repo_root: str = ".") -> list[str]:
    """Return the .tf files that differ between `base` and `head` (repo-relative paths)."""
    _verify_commit(repo_root, base)
    _verify_commit(repo_root, head)
    r = _git(repo_root, "diff", "--name-only", base, head, "--", "*.tf")
    if r.returncode != 0:
        raise RuntimeError(f"git diff failed: {r.stderr.strip()}")
    return sorted(line for line in r.stdout.splitlines() if line.strip())


def _read_at_ref(repo_root: str, ref: str, path: str) -> str | None:
    """File contents at `ref`, or None if the file doesn't exist there (new or deleted)."""
    r = _git(repo_root, "show", f"{ref}:{path}")
    return r.stdout if r.returncode == 0 else None


# --------------------------------------------------------------------- value conversion


def _unquote(value: object) -> str:
    """Turn an hcl2 string value into a plain Python string, or raise _Unsupported."""
    if not isinstance(value, str):
        raise _Unsupported(f"expected a string, got {type(value).__name__}")
    if "${" in value or "%{" in value:
        raise _Unsupported("uses a Terraform expression or interpolation")
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        try:
            return json.loads(value)  # HCL string escapes match JSON's for practical input
        except ValueError as e:
            raise _Unsupported("string literal could not be decoded") from e
    return value


def _string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        raise _Unsupported("expected a literal list")
    return [_unquote(v) for v in value]


def _principals(blocks: object) -> dict | str:
    if not isinstance(blocks, list):
        raise _Unsupported("principals must be blocks")
    merged: dict[str, list[str]] = {}
    for b in blocks:
        if set(b) - {"type", "identifiers", _BLOCK_MARKER}:
            raise _Unsupported("unexpected key in principals block")
        ptype = _unquote(b.get("type"))
        merged.setdefault(ptype, []).extend(_string_list(b.get("identifiers", [])))
    if list(merged) == ["*"] and merged["*"] == ["*"]:
        return "*"  # Terraform renders type="*", identifiers=["*"] as Principal: "*"
    return merged


def _conditions(blocks: object) -> dict:
    if not isinstance(blocks, list):
        raise _Unsupported("condition must be blocks")
    out: dict[str, dict[str, list[str]]] = {}
    for b in blocks:
        if set(b) - {"test", "variable", "values", _BLOCK_MARKER}:
            raise _Unsupported("unexpected key in condition block")
        test, var = _unquote(b.get("test")), _unquote(b.get("variable"))
        out.setdefault(test, {}).setdefault(var, []).extend(_string_list(b.get("values", [])))
    return out


def _statement(block: dict) -> dict:
    extra = set(block) - _STATEMENT_KEYS
    if extra:
        raise _Unsupported(f"unsupported statement field(s): {', '.join(sorted(extra))}")
    stmt: dict = {}
    if "sid" in block:
        stmt["Sid"] = _unquote(block["sid"])
    stmt["Effect"] = _unquote(block["effect"]) if "effect" in block else "Allow"
    for tf_key, iam_key in _LIST_FIELDS.items():
        if tf_key in block:
            stmt[iam_key] = _string_list(block[tf_key])
    if "principals" in block:
        stmt["Principal"] = _principals(block["principals"])
    if "not_principals" in block:
        stmt["NotPrincipal"] = _principals(block["not_principals"])
    if "condition" in block:
        stmt["Condition"] = _conditions(block["condition"])
    return stmt


def _policy_document_from_data(body: dict) -> dict:
    extra = set(body) - _DOC_KEYS
    if extra:
        raise _Unsupported(f"unsupported field(s): {', '.join(sorted(extra))}")
    doc: dict = {"Version": _unquote(body["version"]) if "version" in body else "2012-10-17"}
    if "policy_id" in body:
        doc["Id"] = _unquote(body["policy_id"])
    statements = body.get("statement", [])
    if not isinstance(statements, list):
        raise _Unsupported("statement must be blocks")
    doc["Statement"] = [_statement(s) for s in statements]
    return doc


def _policy_document_from_string(value: object) -> dict:
    if not isinstance(value, str):
        raise _Unsupported("policy is not a string")
    raw = value[1:-1] if len(value) >= 2 and value[0] == value[-1] == '"' else value
    m = _HEREDOC_RE.match(raw)
    if m:
        text = m.group(2)
        if "${" in text or "%{" in text:
            raise _Unsupported("heredoc uses Terraform interpolation")
    elif raw.lstrip().startswith("${"):
        raise _Unsupported("policy is a Terraform expression (jsonencode, file, reference, ...)")
    else:
        text = _unquote(value)
    try:
        doc = json.loads(text)
    except ValueError as e:
        raise _Unsupported("policy is not valid JSON") from e
    if not isinstance(doc, dict):
        raise _Unsupported("policy JSON is not an object")
    return doc


# ------------------------------------------------------------------------ main entry point


def _blocks(parsed: dict, kind: str):
    """Yield (type, name, body) for every `kind` block ("data" or "resource")."""
    for entry in parsed.get(kind, []):
        for btype, named in entry.items():
            for bname, body in named.items():
                yield _unquote(btype), _unquote(bname), body


def _extract_file(path: str, text: str, out: Extraction) -> None:
    try:
        parsed = hcl2.loads(text)
    except Exception:  # noqa: BLE001 - any parse failure is reported, never fatal
        out.unsupported[f"{path}::<file>"] = "could not parse HCL"
        return

    data_doc_names: set[str] = set()
    for btype, name, body in _blocks(parsed, "data"):
        if btype != POLICY_DOC_DATA_TYPE:
            continue
        data_doc_names.add(name)
        pid = f"{path}::data.{btype}.{name}"
        try:
            out.policies[pid] = _policy_document_from_data(body)
        except _Unsupported as e:
            out.unsupported[pid] = str(e)

    for btype, name, body in _blocks(parsed, "resource"):
        if btype not in INLINE_POLICY_RESOURCE_TYPES or "policy" not in body:
            continue
        pid = f"{path}::{btype}.{name}"
        ref = _DATA_DOC_REF_RE.match(body["policy"]) if isinstance(body["policy"], str) else None
        if ref and ref.group(1) in data_doc_names:
            continue  # the referenced data document in this file is already analyzed
        try:
            out.policies[pid] = _policy_document_from_string(body["policy"])
        except _Unsupported as e:
            out.unsupported[pid] = str(e)


def extract_policies(repo_root: str, ref: str, paths: list[str]) -> Extraction:
    """Return every IAM policy found in `paths` at git `ref`.

    policy_id = "<path>::<terraform address>", e.g.
    "examples/demo/main.tf::data.aws_iam_policy_document.app".
    Files that don't exist at `ref` (new or deleted in the PR) contribute nothing.
    """
    _verify_commit(repo_root, ref)
    out = Extraction()
    for path in paths:
        text = _read_at_ref(repo_root, ref, path)
        if text is not None:
            _extract_file(path, text, out)
    return out
