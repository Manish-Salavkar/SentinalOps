from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.trivy_feature.routes import router as trivy_router
from app.trivy_feature.routes import srouter as sonar_router
from app.github_actions.routes import router as github_router

app = FastAPI(title="DevSecOps Vulnerability Dashboard")

origins = [
    "http://localhost:5173",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,  # or ["*"] for testing
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(trivy_router)
app.include_router(sonar_router)
app.include_router(github_router)
