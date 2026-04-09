from fastapi import APIRouter, Request
from app.config import Config
from app.database import db
import requests
import json

router = APIRouter(
    prefix="/api/trivy",
    tags=["Trivy Scans"]
)

@router.post("/ingest")
async def ingest_trivy_scan(payload: dict):
    run_id = payload.get("pipeline", {}).get("run_id")
    await db.trivy.insert_one({
        "run_id": run_id,
        "data": payload
    })

    return {
        "status": "stored",
        "run_id": run_id
    }


srouter = APIRouter(
    prefix="/api/sonarqube",
    tags=["SonarQube Scans"]
)


@srouter.post("/webhook")
async def ingest_sonarqube_scan(request: Request):

    trigger_payload = await request.json()
    project_key = trigger_payload.get("project", {}).get("key")

    if not project_key:
        return {"error": "No project key found in webhook"}

    metrics_response = requests.get(
        f"{Config.SONAR_API_BASE}/measures/component",
        params={
            "component": project_key,
            "metricKeys": "vulnerabilities,bugs,security_rating,security_hotspots"
        }
    )

    issues_response = requests.get(
        f"{Config.SONAR_API_BASE}/issues/search",
        params={
            "componentKeys": project_key,
            "types": "VULNERABILITY"
        }
    )

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

    revision = trigger_payload.get("trigger", {}).get("revision")
    run_id = trigger_payload.get("run_id")

    with open(f"sonarqube.json", "w") as f:
        json.dump(deep_scan_data, f, indent=4)

    await db.sonarqube.insert_one({
        "revision": revision,
        "run_id": run_id,
        "type": "sonarqube",
        "data": deep_scan_data,
    })

    return {
        "status": "stored",
        "run_id": run_id
    }