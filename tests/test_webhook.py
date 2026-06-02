# tests/test_webhook.py

import pytest
from app.main import app
from unittest.mock import patch
import json, hmac, hashlib
from app.config import Config
from httpx import AsyncClient, ASGITransport

transport = ASGITransport(app=app)

@pytest.mark.asyncio
@patch("app.github_actions.routes.jobs_worker")  # 👈 mock worker
async def test_github_webhook_valid_signature(mock_worker):
    payload = {
        "workflow_run": {
            "id": 123,
            "jobs_url": "http://fake-url",
            "status": "completed",
            "run_attempt": 1
        }
    }

    body = json.dumps(payload).encode()

    signature = "sha256=" + hmac.new(
        Config.GITHUB_SECRET.encode(),
        body,
        hashlib.sha256
    ).hexdigest()

    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        response = await ac.post(
            "/github-actions/webhook",
            content=body,
            headers={"x-hub-signature-256": signature}
        )

    assert response.status_code == 200