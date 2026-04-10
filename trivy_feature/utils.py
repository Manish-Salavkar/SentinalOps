import json
from collections import defaultdict
from app.config import Config
from app.database import db
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



async def ingest_trivy_scan(payload: dict):
    run_id = payload.get("pipeline", {}).get("run_id")
    await db.trivy.insert_one({
        "run_id": run_id,
        "data": payload
    })
    print(f"Ingested Trivy scan for run_id: {run_id}")

async def ingest_secrets_scan(payload: dict, run_id: str):
    await db.secrets.insert_one({
        "run_id": run_id,
        "data": payload
    })
    print(f"Ingested Secrets scan for run_id: {run_id}")