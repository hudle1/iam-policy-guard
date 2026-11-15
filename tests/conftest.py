import pathlib
import subprocess

import pytest

FIXTURES = pathlib.Path(__file__).parent / "fixtures"


class GitRepo:
    """A throwaway git repo for tests. Files are given as {repo path: text content}."""

    def __init__(self, path: pathlib.Path):
        self.path = path
        self.git("init", "-q")

    def git(self, *args: str) -> str:
        return subprocess.run(  # noqa: S603
            ["git", "-c", "user.name=test", "-c", "user.email=test@example.com", *args],  # noqa: S607
            cwd=self.path,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()

    def commit(self, files: dict[str, str], message: str = "commit") -> str:
        for dest, content in files.items():
            target = self.path / dest
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
        self.git("add", "-A")
        self.git("commit", "-q", "--allow-empty", "-m", message)
        return self.git("rev-parse", "HEAD")

    @staticmethod
    def fixture(name: str) -> str:
        return (FIXTURES / name).read_text(encoding="utf-8")


@pytest.fixture
def gitrepo(tmp_path: pathlib.Path) -> GitRepo:
    return GitRepo(tmp_path)
