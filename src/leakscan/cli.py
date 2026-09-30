import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

from .engine import Scanner
from .gitscan import GitError, scan_history
from .remote import RemoteError, is_remote, shallow_clone
from .reporters import to_sarif
from .walker import scan_path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="leakscan", description="Scan for leaked secrets and credentials."
    )
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="scan a file, directory, or GitHub URL")
    scan.add_argument(
        "path", help="file, directory, or https://github.com/owner/repo URL"
    )
    scan.add_argument(
        "--format", choices=["console", "json", "sarif"], default="console",
        help="output format (default: console)",
    )
    scan.add_argument(
        "--history", action="store_true",
        help="scan the full git history (default branch only for URLs)",
    )
    return parser


def print_console(findings) -> None:
    if not findings:
        print("No secrets found.")
        return
    for f in findings:
        where = f"{f.file}:{f.line}"
        if f.commit:
            where += f" @ {f.commit}"
        print(
            f"[{f.severity.value.upper():8}] {f.rule_id:26} "
            f"{where}  {f.secret_redacted}  (confidence {f.confidence:.2f})"
        )
    print(f"\n{len(findings)} potential secret(s) found.")


def run_scan(path: Path, scanner: Scanner, history: bool):
    if history:
        return scan_history(path, scanner)
    return scan_path(path, scanner)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    scanner = Scanner()

    try:
        if is_remote(args.path):
            with shallow_clone(args.path, full_history=args.history) as repo:
                findings = run_scan(repo, scanner, args.history)
        else:
            path = Path(args.path)
            if not path.exists():
                print(f"error: path not found: {path}", file=sys.stderr)
                return 2
            findings = run_scan(path, scanner, args.history)
    except (GitError, RemoteError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.format == "json":
        payload = [{**asdict(f), "severity": f.severity.value} for f in findings]
        print(json.dumps(payload, indent=2))
    elif args.format == "sarif":
        print(json.dumps(to_sarif(findings), indent=2))
    else:
        print_console(findings)

    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())