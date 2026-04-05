from fastapi import APIRouter, Request, Header, HTTPException
import hmac
import hashlib
import os
from app.config import Config
import json
from app.github_actions.utils import get_jobs
import asyncio


router = APIRouter(prefix="/github-actions", tags=["GitHub Actions"])


def verify_signature(payload_body: bytes, signature: str):
    mac = hmac.new(Config.GITHUB_SECRET.encode(), payload_body, hashlib.sha256)
    expected = "sha256=" + mac.hexdigest()

    print("Expected:", expected)
    print("Received:", signature)
    print("GITHUB SECRET:", Config.GITHUB_SECRET)
    return hmac.compare_digest(expected, signature)



@router.get("/jobs/live")
async def get_github_jobs_live():
    with open("app/github_actions/payload.json", "r") as file:
        data = json.load(file)
        jobs_url = data["workflow_run"]["jobs_url"]

    timeout = 30
    interval = 3
    elapsed = 0

    while elapsed < timeout:
        jobs_data = await get_jobs(jobs_url)

        if jobs_data:
            job = jobs_data["jobs"][0]

            if job["status"] != "completed":
                return {
                    "status": "running",
                    "jobs": jobs_data
                }

            return {
                "status": "completed",
                "jobs": jobs_data
            }
    
        await asyncio.sleep(interval)
        elapsed += interval
    return {"status": "timeout"}
    

@router.post("/webhook")
async def github_webhook(
    request: Request,
    x_hub_signature_256: str = Header(None),
    x_github_event: str = Header(None)
):
    body = await request.body()
    print("Signature header:", x_hub_signature_256)
    if not verify_signature(body, x_hub_signature_256):
        raise HTTPException(status_code=403, detail="Invalid signature")

    payload = await request.json()

    # Extract and pass the url for long polling
    if payload["workflow_run"]["jobs_url"]:
        pass

    with open("payload.json", "w") as f:
        json.dump(payload, f, indent=4)

    return {"status": "ok"}