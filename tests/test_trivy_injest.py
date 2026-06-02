# tests/test_trivy_ingest.py

import pytest
from app.main import app
from unittest.mock import patch
from httpx import AsyncClient, ASGITransport

transport = ASGITransport(app=app)

@pytest.mark.asyncio
@patch("app.trivy_feature.utils.ingest_trivy_scan")
@patch("app.trivy_feature.utils.ingest_secrets_scan")
async def test_trivy_ingestion(mock_secrets, mock_trivy):
    payload = {
        "pipeline": {"run_id": "123"},
        "scans": {
            "trivy": {"Results": []},
            "secrets": {"data": ["fake"]}
        }
    }

    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        response = await ac.post("/api/trivy/ingest", json=payload)

    assert response.status_code == 200