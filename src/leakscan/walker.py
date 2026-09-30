import os
from collections.abc import Iterator
from pathlib import Path

from .engine import Scanner
from .models import Finding

MAX_FILE_SIZE = 1_000_000  # bytes

SKIP_DIRS = {
    ".git", ".venv", "venv", "node_modules", "__pycache__",
    ".pytest_cache", "dist", "build", ".next", ".idea", ".vscode",
}
SKIP_FILENAMES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock"}
SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".pdf", ".zip",
    ".gz", ".tar", ".exe", ".dll", ".so", ".pyc", ".woff", ".woff2",
    ".ttf", ".mp3", ".mp4",
}


def is_binary(path: Path) -> bool:
    try:
        with open(path, "rb") as f:
            return b"\0" in f.read(1024)
    except OSError:
        return True


def iter_files(root: Path, max_size: int = MAX_FILE_SIZE) -> Iterator[Path]:
    if root.is_file():
        yield root
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            path = Path(dirpath) / name
            if path.is_symlink():
                continue
            if name in SKIP_FILENAMES or path.suffix.lower() in SKIP_EXTENSIONS:
                continue
            try:
                if path.stat().st_size > max_size:
                    continue
            except OSError:
                continue
            if is_binary(path):
                continue
            yield path


def scan_path(
    root: str | Path, scanner: Scanner, max_size: int = MAX_FILE_SIZE
) -> list[Finding]:
    root = Path(root)
    findings: list[Finding] = []
    for path in iter_files(root, max_size):
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        label = str(path.relative_to(root)) if root.is_dir() else path.name
        findings.extend(scanner.scan_text(text, file=label))
    return findings