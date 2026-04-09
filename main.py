from fastapi import FastAPI
from app.trivy_feature.routes import router as trivy_router
from app.trivy_feature.routes import srouter as sonar_router
from app.github_actions.routes import router as github_router

app = FastAPI(title="DevSecOps Vulnerability Dashboard")


app.include_router(trivy_router)
app.include_router(sonar_router)
app.include_router(github_router)
