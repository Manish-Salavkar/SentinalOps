import json
import httpx
import requests
import asyncio
from app.github_actions.queue import jobs_queue
from app.config import Config

def load_json_file():
    with open("app/github_actions/payload.json", "r") as file:
        data = json.load(file)
        return data["workflow_run"]["jobs_url"]

# jobs_url = load_json_file()

# request = requests.get(jobs_url)
# if request.status_code == 200:
#     data = request.json()
#     with open("app/github_actions/jobs.json", "w") as file:
#         json.dump(data, file, indent=4)
# else:
#     print(f"Failed to retrieve data. Status code: {request}")


async def get_jobs(jobs_url):
    headers = {
        "Authorization": f"Bearer {Config.GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json"
    }
    async with httpx.AsyncClient() as client:
        response = await client.get(jobs_url, headers=headers)

        if response.status_code == 200:
            return response.json()
        else:
            print("Failed: ", response.status_code)
            print("Response: ", response.text)
            return None
        


async def jobs_worker(jobs_url):
    interval = 3

    try:
        while True:
            jobs_data = await get_jobs(jobs_url)

            if jobs_data:
                await jobs_queue.put(jobs_data)

                job = jobs_data["jobs"][0]

                if job["status"] == "completed":
                    print("Job completed. Stopping worker.")
                    break

            await asyncio.sleep(interval)

    except asyncio.CancelledError:
        print("Worker cancelled")


def extract_trivy_vulns(trivy_doc):
    if not trivy_doc:
        return []

    results = trivy_doc.get("data", {}).get("Results", [])
    vulns_list = []

    for result in results:
        vulns = result.get("Vulnerabilities", [])
        for v in vulns:
            vulns_list.append({
                "package": v.get("PkgName"),
                "installed_version": v.get("InstalledVersion"),
                "vulnerability_id": v.get("VulnerabilityID"),
                "severity": v.get("Severity"),
                "fixed_version": v.get("FixedVersion"),
            })

    return vulns_list