import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

from .engine import Scanner
from .gitscan import GitError, scan_history
from .reporters import to_sarif
from .walker import scan_path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="leakscan", description="Scan for leaked secrets and credentials."
    )
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="scan a file or directory")
    scan.add_argument("path", help="file or directory to scan")
    scan.add_argument(
        "--format", choices=["console", "json", "sarif"], default="console",
        help="output format (default: console)",
    )
    scan.add_argument(
        "--history", action="store_true",
        help="scan the full git history of the repository at PATH",
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


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    path = Path(args.path)
    if not path.exists():
        print(f"error: path not found: {path}", file=sys.stderr)
        return 2

    scanner = Scanner()
    try:
        if args.history:
            findings = scan_history(path, scanner)
        else:
            findings = scan_path(path, scanner)
    except GitError as exc:
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