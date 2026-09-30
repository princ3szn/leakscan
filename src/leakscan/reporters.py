from .models import Finding, Severity

LEVELS = {
    Severity.LOW: "note",
    Severity.MEDIUM: "warning",
    Severity.HIGH: "error",
    Severity.CRITICAL: "error",
}


def to_sarif(findings: list[Finding], tool_version: str = "0.1.0") -> dict:
    rules: dict[str, dict] = {}
    results = []
    for f in findings:
        rules.setdefault(
            f.rule_id,
            {"id": f.rule_id, "shortDescription": {"text": f.description}},
        )
        results.append(
            {
                "ruleId": f.rule_id,
                "level": LEVELS[f.severity],
                "message": {"text": f"{f.description}: {f.secret_redacted}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.file.replace("\\", "/")},
                            "region": {"startLine": f.line},
                        }
                    }
                ],
                "properties": {"confidence": f.confidence, "commit": f.commit},
            }
        )
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "leakscan",
                        "version": tool_version,
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }