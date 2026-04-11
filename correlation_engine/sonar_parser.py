async def parse_sonarqube(data):
    result = {
        "tool": "sonarqube",
        "summary": {},
        "issues": []
    }

    # 🔹 Extract summary
    measures = data["data"]["overall_metrics"]["component"]["measures"]

    for m in measures:
        if m["metric"] == "vulnerabilities":
            result["summary"]["total_vulnerabilities"] = int(m["value"])
        elif m["metric"] == "security_rating":
            result["summary"]["security_rating"] = float(m["value"])
        elif m["metric"] == "bugs":
            result["summary"]["bugs"] = int(m["value"])

    # 🔹 Extract issues
    issues = data["data"]["vulnerabilities"]["issues"]

    for issue in issues:
        result["issues"].append({
            "severity": issue["severity"],
            "type": issue["type"],
            "file": issue["component"].split(":")[-1],
            "line": issue.get("line", None)
        })

    return result