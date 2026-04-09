# app/database.py

from motor.motor_asyncio import AsyncIOMotorClient
from app.config import Config

client = AsyncIOMotorClient(Config.MONGO_URI)

db = client["sentinel_ops"]

trivy_collection = db["trivy"]
sonarqube_collection = db["sonarqube"]
github_collection = db["github"]