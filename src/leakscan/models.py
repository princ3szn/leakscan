from dataclasses import dataclass
from enum import Enum


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class Finding:
    rule_id: str
    description: str
    file: str
    line: int
    secret_redacted: str
    severity: Severity
    confidence: float  # 0.0 to 1.0
    commit: str | None = None
    author: str | None = None
    entropy: float | None = None


def redact(secret: str, keep: int = 4) -> str:
    """Mask a secret, keeping only a few edge characters."""
    if len(secret) <= keep * 3:
        return "*" * len(secret)
    return secret[:keep] + "*" * (len(secret) - keep * 2) + secret[-keep:]