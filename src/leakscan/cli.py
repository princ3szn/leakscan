import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

from .engine import Scanner
from .walker import scan_path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="leakscan", description="Scan for leaked secrets and credentials."
    )
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="scan a file or directory")
    scan.add_argument("path", help="file or directory to scan")
    scan.add_argument(
        "--format", choices=["console", "json"], default="console",
        help="output format (default: console)",
    )
    return parser


def print_console(findings) -> None:
    if not findings:
        print("No secrets found.")
        return
    for f in findings:
        print(
            f"[{f.severity.value.upper():8}] {f.rule_id:26} "
            f"{f.file}:{f.line}  {f.secret_redacted}  (confidence {f.confidence:.2f})"
        )
    print(f"\n{len(findings)} potential secret(s) found.")


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    path = Path(args.path)
    if not path.exists():
        print(f"error: path not found: {path}", file=sys.stderr)
        return 2

    findings = scan_path(path, Scanner())

    if args.format == "json":
        payload = [{**asdict(f), "severity": f.severity.value} for f in findings]
        print(json.dumps(payload, indent=2))
    else:
        print_console(findings)

    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())