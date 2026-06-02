import pytest
from httpx import AsyncClient, ASGITransport
from app.main import app
from unittest.mock import AsyncMock, patch


# ---------- FAKE CURSOR (CRITICAL FIX) ----------
class FakeCursor:
    def __init__(self, data):
        self.data = data

    def sort(self, *args, **kwargs):
        return self

    def __aiter__(self):
        async def generator():
            for item in self.data:
                yield item
        return generator()


# ---------- CLIENT ----------
def get_client():
    transport = ASGITransport(app=app)
    return AsyncClient(transport=transport, base_url="http://test")


# ---------- TEST: GET RUNS ----------
@pytest.mark.asyncio
@patch("app.github_actions.routes.db")
async def test_get_runs(mock_db):

    fake_data = [
        {
            "run_id": 1,
            "data": {
                "workflow_run": {
                    "conclusion": "success",
                    "run_started_at": "2026-01-01"
                }
            }
        }
    ]

    # Motor-style mock
    mock_db.github.find = lambda *args, **kwargs: FakeCursor(fake_data)

    async with get_client() as ac:
        response = await ac.get("/github-actions/get-runs")

    assert response.status_code == 200
    data = response.json()

    assert isinstance(data, list)
    assert data[0]["run_id"] == 1
    assert data[0]["conclusion"] == "success"


# ---------- TEST: GET RUN DETAILS ----------
@pytest.mark.asyncio
@patch("app.github_actions.routes.risk_score", new_callable=AsyncMock)
@patch("app.github_actions.routes.db")
async def test_get_run_details(mock_db, mock_risk):

    # GitHub doc
    mock_db.github.find_one = AsyncMock(return_value={
        "run_id": 1,
        "data": {
            "workflow_run": {
                "head_sha": "abc123"
            }
        }
    })

    # Trivy (correct structure)
    mock_db.trivy.find_one = AsyncMock(return_value={
        "data": {
            "Results": []
        }
    })

    # Other collections
    mock_db.secrets.find_one = AsyncMock(return_value={"data": {"data": []}})
    mock_db.jobs_collection.find_one = AsyncMock(return_value={"jobs": []})
    mock_db.sonarqube.find_one = AsyncMock(return_value={"data": {}})

    # Risk score
    mock_risk.return_value = 42

    async with get_client() as ac:
        response = await ac.get("/github-actions/get-runs/1")

    assert response.status_code == 200
    data = response.json()

    assert data["run_id"] == 1
    assert data["risk_score"] == 42
    assert "github" in data
    assert "trivy" in data
    assert "secrets" in data


# ---------- TEST: EMPTY RUNS ----------
@pytest.mark.asyncio
@patch("app.github_actions.routes.db")
async def test_get_runs_empty(mock_db):

    mock_db.github.find = lambda *args, **kwargs: FakeCursor([])

    async with get_client() as ac:
        response = await ac.get("/github-actions/get-runs")

    assert response.status_code == 200
    assert response.json() == []