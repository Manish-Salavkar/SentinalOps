from app.correlation_engine.sonar_parser import parse_sonarqube
from app.correlation_engine.trivy_parser import parse_trivy
from app.correlation_engine.secret_parser import parse_secrets
from app.correlation_engine.corelogic import evaluate_security
from app.database import db


async def risk_score(trivy_raw, secrets_raw, sonarqube_raw):

    # Parse
    sonar = await parse_sonarqube(sonarqube_raw)
    trivy = await parse_trivy(trivy_raw)
    secrets = await parse_secrets(secrets_raw)

    # Evaluate
    result = await evaluate_security(sonar, trivy, secrets)
    return result
