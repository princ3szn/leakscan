from leakscan.engine import Scanner
from leakscan.reporters import to_sarif


def test_sarif_structure():
    text = 'key = "' + "AKIA" + "QYZ3TWM5PXLK7B2D" + '"'
    findings = Scanner().scan_text(text, file="src\\app.py")
    doc = to_sarif(findings)
    assert doc["version"] == "2.1.0"
    result = doc["runs"][0]["results"][0]
    location = result["locations"][0]["physicalLocation"]
    assert result["ruleId"] == "aws-access-key-id"
    assert location["artifactLocation"]["uri"] == "src/app.py"
    assert location["region"]["startLine"] == 1


def test_sarif_with_no_findings_has_empty_results():
    assert to_sarif([])["runs"][0]["results"] == []