def parse_trivy(data):
    result = {
        "tool": "trivy",
        "summary": {
            "total": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0
        },
        "vulnerabilities": []
    }

    for res in data.get("Results", []):
        vulns = res.get("Vulnerabilities", [])
        if not vulns:
            continue

        for v in vulns:
            severity = v.get("Severity", "UNKNOWN")

            result["summary"]["total"] += 1

            if severity == "CRITICAL":
                result["summary"]["critical"] += 1
            elif severity == "HIGH":
                result["summary"]["high"] += 1
            elif severity == "MEDIUM":
                result["summary"]["medium"] += 1
            elif severity == "LOW":
                result["summary"]["low"] += 1

            result["vulnerabilities"].append({
                "id": v.get("VulnerabilityID"),
                "package": v.get("PkgName"),
                "severity": severity
            })

    return result