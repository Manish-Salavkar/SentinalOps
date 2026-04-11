async def parse_secrets(data):
    result = {
        "tool": "secrets",
        "summary": {
            "total": 0,
            "high": 0,
            "medium": 0,
            "low": 0
        },
        "findings": []
    }
    print(data)
    findings = data.get("data", [])

    for f in findings:
        severity = f.get("severity", "LOW")

        result["summary"]["total"] += 1

        if severity == "HIGH":
            result["summary"]["high"] += 1
        elif severity == "MEDIUM":
            result["summary"]["medium"] += 1
        elif severity == "LOW":
            result["summary"]["low"] += 1

        result["findings"].append({
            "file": f.get("file"),
            "line": f.get("line"),
            "type": f.get("type"),
            "severity": severity
        })

    return result