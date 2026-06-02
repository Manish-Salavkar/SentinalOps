# tests/test_websocket.py

from fastapi.testclient import TestClient
from app.main import app
from app.github_actions.queue import jobs_queue
import asyncio

client = TestClient(app)

def test_websocket_jobs():
    # preload queue BEFORE connection
    asyncio.run(jobs_queue.put({"job": "test_job"}))

    with client.websocket_connect("/github-actions/ws/jobs") as websocket:
        msg = websocket.receive_json()
        assert msg["msg"] == "connected"

        data = websocket.receive_json()
        assert data["job"] == "test_job"