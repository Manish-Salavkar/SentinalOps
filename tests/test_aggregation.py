# tests/test_aggregation.py

import pytest
from app.main import app
from unittest.mock import AsyncMock, patch
from httpx import AsyncClient, ASGITransport

transport = ASGITransport(app=app)

@pytest.mark.asyncio
@patch("app.github_actions.routes.db")
async def test_get_run_not_found(mock_db):
    mock_db.github.find_one = AsyncMock(return_value=None)

    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        response = await ac.get("/github-actions/get-runs/999")

    assert response.json()["error"] == "Run not found"