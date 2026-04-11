# app/database.py

from motor.motor_asyncio import AsyncIOMotorClient
from app.config import Config

client = AsyncIOMotorClient(Config.MONGO_URI)

db = client["sentinel_ops"]

trivy_collection = db["trivy"]
sonarqube_collection = db["sonarqube"]
github_collection = db["github"]
secrets_collection = db["secrets"]
jobs_collection = db["jobs"]


async def clean(doc):
        if not doc:
            return None
        doc.pop("_id", None)
        return doc