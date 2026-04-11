import json
from SentinalOps.correlation_engine.sonar_parser import parse_sonarqube
from SentinalOps.correlation_engine.trivy_parser import parse_trivy
from SentinalOps.correlation_engine.secret_parser import parse_secrets
from correlation_engine import evaluate_security


def load_json(path):
    with open(path, "r") as f:
        return json.load(f)


def main():
    # Load raw data
    sonar_raw = load_json("sonar.json")
    trivy_raw = load_json("trivy.json")
    secrets_raw = load_json("secrets.json")

    # Parse
    sonar = parse_sonarqube(sonar_raw)
    trivy = parse_trivy(trivy_raw)
    secrets = parse_secrets(secrets_raw)

    # Evaluate
    result = evaluate_security(sonar, trivy, secrets)

    print("\n=== SECURITY REPORT ===")
    print(json.dumps(result, indent=4))


if __name__ == "__main__":
    main()