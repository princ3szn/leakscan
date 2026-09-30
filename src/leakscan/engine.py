import re
import tomllib
from dataclasses import dataclass
from pathlib import Path

from .entropy import shannon_entropy
from .models import Finding, Severity, redact

DEFAULT_RULES_PATH = Path(__file__).parent / "rules" / "default_rules.toml"

PLACEHOLDER_MARKERS = (
    "example", "your", "changeme", "placeholder", "xxxx",
    "dummy", "sample", "<", "${", "{{",
)
# Values published in vendor documentation. They are never real credentials.
KNOWN_EXAMPLES = {
    "AKIA" + "IOSFODNN7EXAMPLE",
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
}
IGNORE_MARKER = "leakscan:ignore"


@dataclass(frozen=True)
class Rule:
    id: str
    description: str
    severity: Severity
    confidence: float
    pattern: re.Pattern
    group: int = 0
    min_entropy: float | None = None


def load_rules(path: Path = DEFAULT_RULES_PATH) -> list[Rule]:
    with open(path, "rb") as f:
        data = tomllib.load(f)
    return [
        Rule(
            id=r["id"],
            description=r["description"],
            severity=Severity(r["severity"]),
            confidence=r["confidence"],
            pattern=re.compile(r["regex"]),
            group=r.get("group", 0),
            min_entropy=r.get("min_entropy"),
        )
        for r in data["rules"]
    ]


def looks_like_placeholder(value: str) -> bool:
    lowered = value.lower()
    return any(marker in lowered for marker in PLACEHOLDER_MARKERS)


class Scanner:
    def __init__(self, rules: list[Rule] | None = None):
        rules = rules if rules is not None else load_rules()
        # Specific rules run first so the generic rules do not double-report.
        self.rules = sorted(rules, key=lambda r: r.min_entropy is not None)

    def scan_text(
        self,
        text: str,
        file: str = "<memory>",
        commit: str | None = None,
        author: str | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        for lineno, line in enumerate(text.splitlines(), start=1):
            if IGNORE_MARKER in line:
                continue
            seen: set[str] = set()
            for rule in self.rules:
                for match in rule.pattern.finditer(line):
                    secret = match.group(rule.group)
                    if secret in seen or secret in KNOWN_EXAMPLES:
                        continue
                    entropy = shannon_entropy(secret)
                    if rule.min_entropy is not None:
                        if looks_like_placeholder(secret) or secret.isdigit():
                            continue
                        if entropy < rule.min_entropy:
                            continue
                    seen.add(secret)
                    findings.append(
                        Finding(
                            rule_id=rule.id,
                            description=rule.description,
                            file=file,
                            line=lineno,
                            secret_redacted=redact(secret),
                            severity=rule.severity,
                            confidence=rule.confidence,
                            commit=commit,
                            author=author,
                            entropy=round(entropy, 2),
                        )
                    )
        return findings