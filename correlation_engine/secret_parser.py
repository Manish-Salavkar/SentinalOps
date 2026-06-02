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

    if not data:
        return result

    # print("RAW DATA:", data)
    # print("TYPE:", type(data))

    findings = data.get("data", {}).get("data", [])

    # print("FINDINGS:", findings)

    if not isinstance(findings, list):
        print("Findings not list, skipping")
        return result

    for f in findings:
        if not isinstance(f, dict):
            print(f"Skipping invalid entry: {f}")
            continue

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