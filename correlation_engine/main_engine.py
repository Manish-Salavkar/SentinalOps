from app.correlation_engine.sonar_parser import parse_sonarqube
from app.correlation_engine.trivy_parser import parse_trivy
from app.correlation_engine.secret_parser import parse_secrets
from app.correlation_engine.corelogic import evaluate_security
from app.database import db



async def risk_score(trivy_raw=None, secrets_raw=None, sonarqube_raw=None):
# async def risk_score(run_id=None):
#     if run_id:
#         trivy_raw = await db.trivy.find_one({"run_id": str(run_id)})
#         secrets_raw = await db.secrets.find_one({"run_id": str(run_id)})

#         github_doc = await db.github.find_one({"run_id": run_id})
#         head_sha = github_doc.get("data", {}).get("workflow_run", {}).get("head_sha")

#         if head_sha:
#             sonarqube_raw = await db.sonarqube.find_one(
#                 {"data.trigger.revision": head_sha}
#             )
            
    sonar = await parse_sonarqube(sonarqube_raw)
    trivy = await parse_trivy(trivy_raw)
    secrets = await parse_secrets(secrets_raw)
    print(secrets)
    # Evaluate
    result = await evaluate_security(sonar, trivy, secrets)
    return result
