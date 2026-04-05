from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session
from app.database import get_db
from app.trivy_feature.models import ScanRun, VulnerabilityRecord
from app.config import Config
import requests
import json
import uuid
import os

router = APIRouter(
    prefix="/api/trivy",
    tags=["Trivy Scans"]
)

@router.post("/ingest")
async def ingest_trivy_scan(payload: dict, db: Session = Depends(get_db)):
    """
    Receives any raw JSON from Trivy, saves the raw file as a backup, 
    and defensively parses required fields into the SQLite database.
    """
    
    # 1. Generate a fallback Report ID if Trivy didn't provide one
    report_id = payload.get("ReportID", str(uuid.uuid4()))
    
    # 2. Save the raw, unadulterated JSON dump first
    # Creating a directory for dumps keeps the root folder clean
    os.makedirs("app/trivy_dumps", exist_ok=True)
    dump_path = f"app/trivy_dumps/scan_{report_id}.json"
    
    with open(dump_path, "w") as f:
        json.dump(payload, f, indent=4)
        
    print(f"Successfully saved raw scan to {dump_path}")

    # 3. Defensively extract metadata for the ScanRun model
    # Using .get() ensures we get None or an empty dict instead of a crash
    trivy_info = payload.get("Trivy", {})
    metadata = payload.get("Metadata", {})
    os_info = metadata.get("OS", {})

    new_scan = ScanRun(
        report_id=report_id,
        trivy_version=trivy_info.get("Version", "unknown"),
        artifact_name=payload.get("ArtifactName", "unknown"),
        artifact_type=payload.get("ArtifactType", "unknown"),
        os_family=os_info.get("Family"),
        os_name=os_info.get("Name")
    )
    
    db.add(new_scan)
    db.commit()
    db.refresh(new_scan)

    # 4. Defensively extract and save Vulnerabilities
    vuln_records = []
    
    # payload.get("Results") might return None if the scan was completely clean
    results = payload.get("Results") or [] 
    
    for result in results:
        vulns = result.get("Vulnerabilities") or []
        for vuln in vulns:
            new_vuln = VulnerabilityRecord(
                scan_id=new_scan.id,
                vulnerability_id=vuln.get("VulnerabilityID", "UNKNOWN_CVE"),
                pkg_name=vuln.get("PkgName", "unknown_pkg"),
                installed_version=vuln.get("InstalledVersion", "unknown"),
                fixed_version=vuln.get("FixedVersion"),
                severity=vuln.get("Severity", "UNKNOWN")
            )
            vuln_records.append(new_vuln)

    if vuln_records:
        db.bulk_save_objects(vuln_records)
        db.commit()

    return {
        "status": "success", 
        "scan_id": new_scan.id, 
        "vulnerabilities_parsed": len(vuln_records),
        "backup_file": dump_path
    }


srouter = APIRouter(
    prefix="/api/sonarqube",
    tags=["SonarQube Scans"]
)


@srouter.post("/webhook")
async def ingest_sonarqube_scan(request: Request, db: Session = Depends(get_db)):
    # 1. Catch the lightweight trigger payload
    trigger_payload = await request.json()
    project_key = trigger_payload.get("project", {}).get("key")
    
    if not project_key:
        return {"error": "No project key found in webhook"}

    print(f"Webhook received for {project_key}. Fetching deep metrics...")

    # 2. Fetch the Overall Risk Metrics
    metrics_url = f"{Config.SONAR_API_BASE}/measures/component"
    metrics_params = {
        "component": project_key,
        "metricKeys": "vulnerabilities,bugs,security_rating,security_hotspots"
    }
    
    # 3. Fetch the Actual Vulnerabilities (The SQL Injections, etc.)
    issues_url = f"{Config.SONAR_API_BASE}/issues/search"
    issues_params = {
        "componentKeys": project_key,
        "types": "VULNERABILITY" 
    }

    # BOOM: No auth parameters needed because the project is Public!
    metrics_response = requests.get(metrics_url, params=metrics_params)
    issues_response = requests.get(issues_url, params=issues_params)

    # Combine everything into one massive, useful JSON object
    deep_scan_data = {
        "trigger": trigger_payload,
        "overall_metrics": metrics_response.json() if metrics_response.status_code == 200 else {
            "error_code": metrics_response.status_code,
            "reason": metrics_response.text
        },
        "vulnerabilities": issues_response.json() if issues_response.status_code == 200 else {
            "error_code": issues_response.status_code,
            "reason": issues_response.text
        }
    }

    # 4. Save the deep data dump
    task_id = trigger_payload.get("taskId", str(uuid.uuid4()))
    os.makedirs("app/sonarqube_dumps", exist_ok=True)
    dump_path = f"app/sonarqube_dumps/deep_scan_{task_id}.json"
    
    with open(dump_path, "w") as f:
        json.dump(deep_scan_data, f, indent=4)
        
    print(f"Successfully fetched and saved deep SonarCloud scan to {dump_path}")
    
    return {"status": "success", "fetched_deep_data": True}


