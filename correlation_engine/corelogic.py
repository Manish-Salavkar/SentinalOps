async def evaluate_security(sonar, trivy, secrets):
    reasons = []
    risk = 0

    sonar_vulns = sonar["summary"].get("total_vulnerabilities", 0)
    if sonar_vulns > 0:
        risk += sonar_vulns * 2
        reasons.append(f"{sonar_vulns} code vulnerabilities found")


    critical = trivy["summary"].get("critical", 0)
    high = trivy["summary"].get("high", 0)

    if critical > 0:
        risk += critical * 5
        reasons.append(f"{critical} critical container vulnerabilities")

    if high > 0:
        risk += high * 3

    secret_high = secrets["summary"].get("high", 0)

    if secret_high > 0:
        risk += secret_high * 10
        reasons.append(f"{secret_high} secrets exposed")

    if critical > 0 or secret_high > 0:
        status = "FAIL"
    elif risk > 10:
        status = "FAIL"
    else:
        status = "PASS"

    return {
        "status": status,
        "risk_score": risk,
        "reasons": reasons
    }