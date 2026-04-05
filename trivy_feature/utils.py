import json
from collections import defaultdict
from app.config import Config
import os

def extract_trivy_vulnerabilities(data: dict):
    output = {
        "artifact": {
            "name": data.get("ArtifactName"),
            "type": data.get("ArtifactType"),
            "os": data.get("Metadata", {}).get("OS", {})
        },
        "summary": {
            "total": 0,
            "severity_counts": defaultdict(int)
        },
        "vulnerabilities": []
    }

    results = data.get("Results") or []

    for result in results:
        target = result.get("Target")
        vulns = result.get("Vulnerabilities") or []

        for v in vulns:
            vuln = {
                "cve_id": v.get("VulnerabilityID"),
                "package": v.get("PkgName"),
                "installed_version": v.get("InstalledVersion"),
                "fixed_version": v.get("FixedVersion"),
                "severity": v.get("Severity"),
                "title": v.get("Title"),
                "target": target,
            }

            output["vulnerabilities"].append(vuln)

            severity = vuln["severity"] or "UNKNOWN"
            output["summary"]["severity_counts"][severity] += 1
            output["summary"]["total"] += 1

    output["summary"]["severity_counts"] = dict(output["summary"]["severity_counts"])

    return output

trivy_path = Config.TRIVY_DUMPS_DIR
print("Trivy dumps path:", trivy_path)

files = [
    f for f in os.listdir(trivy_path)
    if f.endswith(".json")
]

if not files:
    raise FileNotFoundError("No Trivy JSON files found")

# pick latest file
latest_file = max(
    files,
    key=lambda f: os.path.getmtime(os.path.join(trivy_path, f))
)

latest_file_path = os.path.join(trivy_path, latest_file)

print(f"Using file: {latest_file_path}")

# read + process
with open(latest_file_path) as f:
    trivy_data = json.load(f)

vulnerabilities = extract_trivy_vulnerabilities(trivy_data)

print(json.dumps(vulnerabilities, indent=2))