from fastapi import APIRouter, Request, Header, HTTPException, WebSocket
from datetime import datetime
import hmac
import hashlib
from app.config import Config
from app.github_actions.utils import get_jobs, jobs_worker, extract_trivy_vulns
from app.github_actions.queue import jobs_queue
from app.database import db
import asyncio


router = APIRouter(prefix="/github-actions", tags=["GitHub Actions"])


def verify_signature(payload_body: bytes, signature: str):
    mac = hmac.new(Config.GITHUB_SECRET.encode(), payload_body, hashlib.sha256)
    expected = "sha256=" + mac.hexdigest()

    # print("Expected:", expected)
    # print("Received:", signature)
    # print("GITHUB SECRET:", Config.GITHUB_SECRET)
    return hmac.compare_digest(expected, signature)


processed_runs = set()    

@router.post("/webhook")
async def github_webhook(
    request: Request,
    x_hub_signature_256: str = Header(None),
    x_github_event: str = Header(None)
):
    body = await request.body()
    # print("Signature header:", x_hub_signature_256)
    if not verify_signature(body, x_hub_signature_256):
        raise HTTPException(status_code=403, detail="Invalid signature")

    payload = await request.json()

    workflow = payload.get("workflow_run", {})
    run_id = workflow.get("id")
    jobs_url = workflow.get("jobs_url")
    status = workflow.get("status")
    run_attempt = workflow.get("run_attempt")

    if jobs_url and run_id not in processed_runs:
        processed_runs.add(run_id)
        asyncio.create_task(jobs_worker(jobs_url))

    # with open("payload.json", "w") as f:
    #     json.dump(payload, f, indent=4)
    if status == "completed":
        await db.github.insert_one({
            "run_id": run_id,
            "event": "workflow_run",
            "data": payload,
            "run_attempt": run_attempt
        })
        processed_runs.discard(run_id)
    return {"status": "ok"}



@router.websocket("/ws/jobs")
async def websocket_jobs(ws: WebSocket):
    await ws.accept()

    try:
        while True:
            jobs_data = await jobs_queue.get()  # waits for new data

            await ws.send_json(jobs_data)

    except Exception as e:
        print("WebSocket closed:", e)


@router.get("/get-runs")
async def get_runs():
    cursor = db.github.find(
        {},
        {
            "_id": 0,
            "run_id": 1,
            "data.workflow_run.conclusion": 1,
            "data.workflow_run.run_started_at": 1
        }
    ).sort("data.workflow_run.run_started_at", -1)  # newest first

    results = []

    async for doc in cursor:
        workflow = doc.get("data", {}).get("workflow_run", {})

        results.append({
            "run_id": doc.get("run_id"),
            "conclusion": workflow.get("conclusion"),
            "run_started_at": workflow.get("run_started_at")
        })

    return results


@router.get("/get-runs/{run_id}")
async def get_pipeline_run(run_id: int):
    
    github_doc = await db.github.find_one({"run_id": run_id})

    if not github_doc:
        return {"error": "Run not found"}

    workflow = github_doc.get("data", {}).get("workflow_run", {})
    head_sha = workflow.get("head_sha")

    trivy_doc = await db.trivy.find_one({"run_id": str(run_id)})
    vulnerabilities = extract_trivy_vulns(trivy_doc)

    sonarqube_doc = None
    if head_sha:
        sonarqube_doc = await db.sonarqube.find_one(
            {"data.trigger.revision": head_sha}
        )

    def clean(doc):
        if not doc:
            return None
        doc.pop("_id", None)
        return doc

    return {
        "run_id": run_id,
        "github": clean(github_doc),
        "trivy": vulnerabilities,
        "sonarqube": clean(sonarqube_doc),
        "head_sha": head_sha
    }