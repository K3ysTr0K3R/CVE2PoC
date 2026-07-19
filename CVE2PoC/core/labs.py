import requests
from bs4 import BeautifulSoup as bsoup
import tomli
import re
import os
from urllib.parse import urlparse
from CVE2PoC.core.user_agent import get_user_agent   # your existing module

# ------------------ Helper: GitHub API with token ------------------
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")  # optional, but recommended

def _github_api_request(url, params=None):
    headers = {"Accept": "application/vnd.github.v3+json"}
    if GITHUB_TOKEN:
        headers["Authorization"] = f"token {GITHUB_TOKEN}"
    response = requests.get(url, headers=headers, params=params, timeout=15)
    if response.status_code == 403 and "rate limit" in response.text.lower():
        print("[!] GitHub rate limit reached. Set a GITHUB_TOKEN environment variable to increase quota.")
    elif response.status_code != 200:
        print(f"[!] GitHub API error: {response.status_code}")
    return response

# ------------------ 1. Vulhub (your existing function, adapted) ------------------
def search_pre_built_vulnerable_docker_environments(cve_id):
    """
    Search Vulhub TOML config for a CVE ID.
    Returns a setup string or "N/A".
    """
    try:
        response = requests.get(
            "https://raw.githubusercontent.com/vulhub/vulhub/refs/heads/master/environments.toml",
            headers={"User-Agent": get_user_agent()},
            timeout=10
        )
        response.raise_for_status()
        config = tomli.loads(response.text)
        vulnerable_environments = config.get("environment", [])
        for env in vulnerable_environments:
            cves = env.get("cve", [])
            if cves and cves[0].casefold() == cve_id.casefold():
                path = env["path"]
                return {
                    "source": "Vulhub",
                    "name": f"{cve_id} - {path}",
                    "url": f"https://github.com/vulhub/vulhub/tree/master/{path}",
                    "setup": f"""Follow the steps below to setup your vulnerable Docker environment:
1/ Clone the Vulhub repository (shallow):
   git clone --depth 1 https://github.com/vulhub/vulhub.git
2/ Move to the vulnerability directory:
   cd vulhub/{path}
3/ Start the vulnerable environment:
   docker compose up -d
4/ Reproduction steps: https://github.com/vulhub/vulhub/tree/master/{path}
5/ Clean up after testing:
   docker compose down"""
                }
    except Exception as e:
        print(f"[!] Vulhub search error: {e}")
    return None

# ------------------ 2. GitHub Code Search ------------------
def search_github_docker(cve_id):
    """
    Search GitHub for code (Dockerfiles, compose files) referencing the CVE.
    Returns a list of results (dicts).
    """
    results = []
    # Build query: CVE ID + Docker-related keywords
    query = f'{cve_id} docker-compose OR Dockerfile OR "docker run"'
    url = "https://api.github.com/search/code"
    params = {
        "q": query,
        "per_page": 20,
        "page": 1
    }

    while True:
        resp = _github_api_request(url, params)
        if resp.status_code != 200:
            break
        data = resp.json()
        items = data.get("items", [])
        if not items:
            break
        for item in items:
            repo = item["repository"]["full_name"]
            path = item["path"]
            file_url = item["html_url"]
            # Try to get raw content to check if it's really Docker-related (optional)
            raw_url = item.get("url", "").replace("https://api.github.com/repos", 
                                                  "https://raw.githubusercontent.com") + "/" + path
            # To avoid too many requests, just add the result
            results.append({
                "source": "GitHub",
                "name": f"{repo} - {path}",
                "url": file_url,
                "setup": f"Clone the repository and inspect '{path}' for Docker setup:\n"
                         f"  git clone https://github.com/{repo}.git\n"
                         f"  cd {repo.split('/')[-1]}\n"
                         f"  # Follow instructions in {path}"
            })
        # Pagination
        if "next" in resp.links:
            url = resp.links["next"]["url"]
            params = None   # next url already contains params
        else:
            break
    return results

# ------------------ 3. Docker Hub Search ------------------
def search_dockerhub(cve_id):
    """
    Search Docker Hub for images whose description contains the CVE ID.
    """
    results = []
    url = "https://hub.docker.com/v2/repositories/"
    params = {
        "query": cve_id,
        "page_size": 25,
        "page": 1
    }
    while True:
        try:
            resp = requests.get(url, params=params, timeout=10)
            if resp.status_code != 200:
                break
            data = resp.json()
            for repo in data.get("results", []):
                name = repo.get("name", "")
                namespace = repo.get("namespace", "")
                description = repo.get("description", "")
                if not namespace:
                    namespace = "library"  # official images
                full_name = f"{namespace}/{name}"
                results.append({
                    "source": "Docker Hub",
                    "name": full_name,
                    "url": f"https://hub.docker.com/r/{full_name}",
                    "setup": f"Pull and run the image:\n  docker pull {full_name}\n"
                             f"  # Check the image documentation for how to run it as a vulnerable lab."
                })
            if data.get("next"):
                params = {"page": params["page"] + 1, "page_size": params["page_size"], "query": cve_id}
            else:
                break
        except Exception as e:
            print(f"[!] Docker Hub error: {e}")
            break
    return results

# ------------------ 4. (Optional) Known curated lists ------------------
# You can add more sources here, e.g., Vulfocus, GitLab, etc.

# ------------------ 5. Master aggregator ------------------
def search_all_docker_labs(cve_id):
    """
    Aggregate results from all known Docker lab sources.
    Returns a list of result dicts with keys: source, name, url, setup.
    """
    all_results = []

    # 1. Vulhub
    vulhub_result = search_pre_built_vulnerable_docker_environments(cve_id)
    if vulhub_result:
        all_results.append(vulhub_result)

    # 2. GitHub
    github_results = search_github_docker(cve_id)
    all_results.extend(github_results)

    # 3. Docker Hub
    dockerhub_results = search_dockerhub(cve_id)
    all_results.extend(dockerhub_results)

    # 4. Add more sources as needed...

    # Deduplicate by URL (keep first occurrence)
    seen = set()
    unique = []
    for r in all_results:
        if r["url"] not in seen:
            seen.add(r["url"])
            unique.append(r)
    return unique

# ------------------ Usage example ------------------
if __name__ == "__main__":
    cve = "CVE-2021-44228"
    labs = search_all_docker_labs(cve)
    if labs:
        print(f"Found {len(labs)} Docker labs for {cve}:")
        for lab in labs:
            print(f"\n--- {lab['source']} ---")
            print(f"Name: {lab['name']}")
            print(f"URL: {lab['url']}")
            print(f"Setup:\n{lab['setup']}")
    else:
        print(f"No Docker labs found for {cve}.")
