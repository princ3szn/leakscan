import os
import re
import shutil
import stat
import subprocess
import tempfile
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

GITHUB_URL_RE = re.compile(
    r"https://github\.com/"
    r"([A-Za-z0-9][A-Za-z0-9-]{0,38})/"
    r"([A-Za-z0-9._-]{1,100}?)(?:\.git)?/?"
)
DEFAULT_MAX_BYTES = 100 * 1024 * 1024  # 100 MB
DEFAULT_TIMEOUT = 60  # seconds


class RemoteError(RuntimeError):
    pass


def is_remote(target: str) -> bool:
    return target.lower().startswith(("http://", "https://"))


def parse_github_url(url: str) -> tuple[str, str]:
    match = GITHUB_URL_RE.fullmatch(url.strip())
    if not match:
        raise RemoteError(
            "only URLs like https://github.com/owner/repo are supported"
        )
    owner, repo = match.groups()
    if repo in {".", ".."}:
        raise RemoteError("invalid repository name")
    return owner, repo


def _dir_size(path: Path) -> int:
    total = 0
    for dirpath, _dirs, files in os.walk(path):
        for name in files:
            try:
                total += os.lstat(os.path.join(dirpath, name)).st_size
            except OSError:
                pass
    return total


def _force_remove(func, path, _exc_info) -> None:
    # Git marks object files read-only, which makes rmtree fail on Windows.
    os.chmod(path, stat.S_IWRITE)
    func(path)


@contextmanager
def shallow_clone(
    url: str,
    full_history: bool = False,
    max_bytes: int = DEFAULT_MAX_BYTES,
    timeout: float = DEFAULT_TIMEOUT,
) -> Iterator[Path]:
    owner, repo = parse_github_url(url)
    # Rebuild the URL from validated parts instead of passing user input on.
    clone_url = f"https://github.com/{owner}/{repo}.git"

    tmp = tempfile.mkdtemp(prefix="leakscan-")
    try:
        dest = Path(tmp) / "repo"
        cmd = [
            "git",
            "-c", "core.symlinks=false",
            "-c", "protocol.allow=never",
            "-c", "protocol.https.allow=always",
            "clone", "--single-branch", "--no-tags", "--quiet",
        ]
        if not full_history:
            cmd += ["--depth", "1"]
        cmd += ["--", clone_url, str(dest)]

        env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
        try:
            proc = subprocess.Popen(
                cmd,
                env=env,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except FileNotFoundError as exc:
            raise RemoteError("git executable not found") from exc

        start = time.monotonic()
        while proc.poll() is None:
            if time.monotonic() - start > timeout:
                proc.kill()
                proc.wait()
                raise RemoteError(f"clone timed out after {timeout:.0f}s")
            if _dir_size(dest) > max_bytes:
                proc.kill()
                proc.wait()
                raise RemoteError(
                    f"repository exceeds the {max_bytes // (1024 * 1024)} MB limit"
                )
            time.sleep(0.25)

        if proc.returncode != 0:
            raise RemoteError(
                "clone failed (repository not found, private, or unreachable)"
            )
        yield dest
    finally:
        shutil.rmtree(tmp, onerror=_force_remove)