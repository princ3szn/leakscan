import re
import subprocess
from dataclasses import replace
from pathlib import Path

from .engine import Scanner
from .models import Finding
from .walker import SKIP_DIRS, SKIP_EXTENSIONS, SKIP_FILENAMES

COMMIT_MARKER = "@@COMMIT@@"
HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


class GitError(RuntimeError):
    pass


def _skip(path: str) -> bool:
    p = Path(path)
    return (
        p.name in SKIP_FILENAMES
        or p.suffix.lower() in SKIP_EXTENSIONS
        or any(part in SKIP_DIRS for part in p.parts)
    )


def _ensure_repo(repo: Path) -> None:
    try:
        result = subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "--git-dir"],
            capture_output=True,
        )
    except FileNotFoundError as exc:
        raise GitError("git executable not found") from exc
    if result.returncode != 0:
        raise GitError(f"not a git repository: {repo}")


def scan_history(
    repo: str | Path, scanner: Scanner, max_line_length: int = 2000
) -> list[Finding]:
    repo = Path(repo)
    _ensure_repo(repo)

    cmd = [
        "git", "-C", str(repo), "log", "--all", "-p", "-U0",
        "--no-color", "--no-ext-diff",
        f"--pretty=format:{COMMIT_MARKER}%H%x09%an",
    ]
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        encoding="utf-8",
        errors="replace",
    )

    findings: list[Finding] = []
    commit = author = None
    current_file = None
    in_header = False
    new_line = 0

    for raw in proc.stdout:
        line = raw.rstrip("\n")
        if line.startswith(COMMIT_MARKER):
            sha, _, author = line[len(COMMIT_MARKER):].partition("\t")
            commit = sha[:10]
            current_file = None
            in_header = False
        elif line.startswith("diff --git "):
            in_header = True
            current_file = None
        elif in_header and line.startswith("+++ "):
            target = line[4:]
            if target == "/dev/null":
                current_file = None
            elif target.startswith("b/"):
                current_file = target[2:]
            else:
                current_file = target
        elif line.startswith("@@"):
            in_header = False
            match = HUNK_RE.match(line)
            if match:
                new_line = int(match.group(1))
        elif line.startswith("+") and not in_header:
            if current_file and not _skip(current_file):
                content = line[1:]
                if len(content) <= max_line_length:
                    for f in scanner.scan_text(
                        content, file=current_file, commit=commit, author=author
                    ):
                        findings.append(replace(f, line=new_line))
            new_line += 1

    proc.wait()
    if proc.returncode != 0:
        raise GitError("git log failed (does the repository have any commits?)")
    return findings