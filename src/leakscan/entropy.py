import math
import string
from collections import Counter

HEX_CHARS = set(string.hexdigits)
BASE64_CHARS = set(string.ascii_letters + string.digits + "+/=-_")

# Starting points only. We will tune these against the benchmark corpus.
THRESHOLDS = {"hex": 3.0, "base64": 4.5, "other": 4.5}


def shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def charset_of(token: str) -> str:
    chars = set(token)
    if chars <= HEX_CHARS:
        return "hex"
    if chars <= BASE64_CHARS:
        return "base64"
    return "other"


def is_high_entropy(token: str, min_length: int = 20) -> bool:
    if len(token) < min_length:
        return False
    return shannon_entropy(token) >= THRESHOLDS[charset_of(token)]