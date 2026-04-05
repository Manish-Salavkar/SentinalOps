from fastapi import FastAPI
from app.database import engine
from app.auth import models as auth_models
from app.trivy_feature import models as trivy_models
from app.trivy_feature.routes import router as trivy_router
from app.trivy_feature.routes import srouter as sonar_router
from app.github_actions.routes import router as github_router

app = FastAPI(title="DevSecOps Vulnerability Dashboard")

# Create tables for all models
auth_models.Base.metadata.create_all(bind=engine)
trivy_models.Base.metadata.create_all(bind=engine)

# Include the Trivy routing logic
app.include_router(trivy_router)
app.include_router(sonar_router)
app.include_router(github_router)

# No more business logic here!