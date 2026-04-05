import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

class Config:
    # Database configuration
    DB_URL = os.getenv("DATABASE_URL", "sqlite:///./test.db")

    # Trivy configuration
    TRIVY_DUMPS_PATH = os.getenv("TRIVY_DUMPS_PATH")
    TRIVY_SEVERITY_LEVELS = os.getenv("TRIVY_SEVERITY_LEVELS", "CRITICAL,HIGH,MEDIUM").split(",")

    # SonarQube configuration
    SONAR_API_BASE = os.getenv("SONAR_API_BASE", "https://sonarcloud.io/api")
    SONAR_TOKEN = os.getenv("SONAR_TOKEN", "sonarqube_token")

    # GitHub Actions configuration
    GITHUB_SECRET = os.getenv("GITHUB_SECRET").strip()

    TRIVY_DUMPS_DIR = (
    TRIVY_DUMPS_PATH if os.path.isabs(TRIVY_DUMPS_PATH)
    else os.path.join(BASE_DIR, TRIVY_DUMPS_PATH)
)