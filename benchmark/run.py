import json
import shutil
import subprocess
import tempfile
from pathlib import Path

from corpus import build_cases

from leakscan.engine import Scanner
from leakscan.walker import scan_path


def write_corpus(root: Path, cases) -> set:
    expected = set()
    for case in cases:
        (root / case.filename).write_text("\n".join(case.lines) + "\n", encoding="utf-8")
        for n in case.secret_lines:
            expected.add((case.filename, n))
    return expected


def run_gitleaks(root: Path, report: Path):
    exe = shutil.which("gitleaks")
    if not exe:
        return None
    subprocess.run(
        [exe, "detect", "--no-git", "--source", str(root),
         "--report-format", "json", "--report-path", str(report),
         "--exit-code", "0"],
        capture_output=True,
    )
    if not report.exists():
        return set()
    data = json.loads(report.read_text(encoding="utf-8") or "[]") or []
    return {(Path(d["File"]).name, d["StartLine"]) for d in data}


def score(predicted: set, expected: set):
    tp = len(predicted & expected)
    fp = len(predicted - expected)
    fn = len(expected - predicted)
    precision = tp / (tp + fp) if tp + fp else 1.0
    recall = tp / (tp + fn) if tp + fn else 1.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return tp, fp, fn, precision, recall, f1


def main() -> None:
    cases = build_cases()
    notes = {c.filename: c.note for c in cases}

    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        root = tmp / "corpus"
        root.mkdir()
        expected = write_corpus(root, cases)

        results = {}
        findings = scan_path(root, Scanner())
        results["leakscan"] = {(Path(f.file).name, f.line) for f in findings}

        gitleaks = run_gitleaks(root, tmp / "gitleaks_report.json")
        if gitleaks is None:
            print("(gitleaks not found on PATH, skipping comparison)\n")
        else:
            results["gitleaks"] = gitleaks

    print(f"Corpus: {len(cases)} files, {len(expected)} labeled secrets\n")
    print(f"{'tool':10} {'TP':>4} {'FP':>4} {'FN':>4} {'precision':>10} {'recall':>8} {'F1':>6}")
    for name, predicted in results.items():
        tp, fp, fn, p, r, f1 = score(predicted, expected)
        print(f"{name:10} {tp:>4} {fp:>4} {fn:>4} {p:>10.2f} {r:>8.2f} {f1:>6.2f}")

    predicted = results["leakscan"]
    print("\nleakscan missed:")
    for fname, line in sorted(expected - predicted):
        print(f"  {fname}:{line}  ({notes[fname]})")
    print("\nleakscan false positives:")
    for fname, line in sorted(predicted - expected):
        print(f"  {fname}:{line}  ({notes[fname]})")


if __name__ == "__main__":
    main()