import json
import httpx
import requests
import asyncio


def load_json_file():
    with open("app/github_actions/payload.json", "r") as file:
        data = json.load(file)
        return data["workflow_run"]["jobs_url"]

jobs_url = load_json_file()

request = requests.get(jobs_url)
if request.status_code == 200:
    data = request.json()
    with open("app/github_actions/jobs.json", "w") as file:
        json.dump(data, file, indent=4)
else:
    print(f"Failed to retrieve data. Status code: {request}")


async def get_jobs(jobs_url):
    async with httpx.AsyncClient() as client:
        response = await client.get(jobs_url)

        if response.status_code == 200:
            return response.json()
        else:
            print("Failed: ", response.status_code)
            return None
        