import requests
from bs4 import BeautifulSoup as bsoup
import tomli
import os
import re
from urllib.parse import urlparse

from CVE2PoC.core.user_agent import get_user_agent

# ------------------ Original CTF search (HTB / THM) ------------------
def search_ctf_labs(cve_id):
    """
    Returns HackTheBox and TryHackMe hands-on labs related to a CVE ID.
    """
    labs = {}
    # Searching HTB machines related to CVE ID
    xdf = requests.get("https://0xdf.gitlab.io/tags", {"User-Agent": get_user_agent()})
    soup = bsoup(xdf.text, "html.parser")
    cve_selector = soup.select(f'h2[id="{cve_id}" i] + ul')
    if cve_selector:
        labs["htb"] = (
            "https://www.hackthebox.com/machines/"
            + cve_selector[0].select("a")[0].text.split()[1].lower()
        )
    # Searching THM machines related to CVE ID
    response = requests.get(
        "https://raw.githubusercontent.com/0liverFlow/CVE2PoC-CI/refs/heads/main/latest_thm_rooms.txt",
        {"User-Agent": get_user_agent()},
    )
    thm_machines = response.text.split("\n")
    for machine in thm_machines:
        if machine.split(":", 1)[0].upper() == cve_id.upper():
            labs["thm"] = machine.split(":", 1)[-1]
            break
    return labs

# ------------------ Original Vulhub Docker search (string output) ------------------
def search_pre_built_vulnerable_docker_environments(cve_id):
    """
    Searches Vulhub for a CVE ID and returns a setup string or "N/A".
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
                return f"""Follow the steps below to setup your vulnerable docker environment
1/ Clone the Vulhub repository: [bright_cyan]git clone --depth 1 https://github.com/vulhub/vulhub.git[/bright_cyan]
2/ Move to the vulnerability directory: [bright_cyan]cd vulhub/{path}[/bright_cyan]
3/ Start the vulnerable environment: [bright_cyan]docker compose up -d[/bright_cyan]
4/ Use this resource for reproduction steps: https://github.com/vulhub/vulhub/tree/master/{path}
5/ Clean up after testing: [bright_cyan]docker compose down[/bright_cyan]"""
    except Exception:
        pass
    return "N/A"

# ------------------ NEW: Extended Docker lab search ------------------
# Helper: GitHub API (with optional token)
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")

def _github_api_request(url, params=None):
    headers = {"Accept": "application/vnd.github.v3+json"}
    if GITHUB_TOKEN:
        headers["Authorization"] = f"token {GITHUB_TOKEN}"
    resp = requests.get(url, headers=headers, params=params, timeout=15)
    if resp.status_code == 403 and "rate limit" in resp.text.lower():
        print("[!] GitHub rate limit reached. Set GITHUB_TOKEN environment variable.")
    return resp

def search_github_docker(cve_id):
    """
    Search GitHub for Docker-related files mentioning the CVE.
    Returns a list of result dictionaries.
    """
    results = []
    query = f'{cve_id} docker-compose OR Dockerfile OR "docker run"'
    url = "https://api.github.com/search/code"
    params = {"q": query, "per_page": 20, "page": 1}

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
            results.append({
                "source": "GitHub",
                "name": f"{repo} - {path}",
                "url": file_url,
                "setup": f"Clone the repo and check '{path}':\n"
                         f"  git clone https://github.com/{repo}.git\n"
                         f"  cd {repo.split('/')[-1]}\n"
                         f"  # Follow instructions in {path}"
            })
        # Pagination
        if "next" in resp.links:
            url = resp.links["next"]["url"]
            params = None
        else:
            break
    return results

def search_dockerhub(cve_id):
    """
    Search Docker Hub for images whose description contains the CVE.
    """
    results = []
    url = "https://hub.docker.com/v2/repositories/"
    params = {"query": cve_id, "page_size": 25, "page": 1}

    while True:
        try:
            resp = requests.get(url, params=params, timeout=10)
            if resp.status_code != 200:
                break
            data = resp.json()
            for repo in data.get("results", []):
                name = repo.get("name", "")
                namespace = repo.get("namespace", "library")
                full_name = f"{namespace}/{name}"
                results.append({
                    "source": "Docker Hub",
                    "name": full_name,
                    "url": f"https://hub.docker.com/r/{full_name}",
                    "setup": f"Pull and run:\n  docker pull {full_name}\n"
                             f"  # See documentation for lab setup."
                })
            if data.get("next"):
                params = {"page": params["page"] + 1, "page_size": params["page_size"], "query": cve_id}
            else:
                break
        except Exception:
            break
    return results

def search_additional_docker_sources(cve_id):
    """
    Placeholder for future sources (e.g., Vulfocus, GitLab, CTF platforms).
    """
    return []

def search_all_docker_labs(cve_id):
    """
    Aggregates all Docker lab sources into a list of dictionaries.
    Each dict contains: source, name, url, setup.
    """
    all_results = []

    # Vulhub (already returns a string, we convert to a structured dict)
    vulhub_str = search_pre_built_vulnerable_docker_environments(cve_id)
    if vulhub_str != "N/A":
        all_results.append({
            "source": "Vulhub",
            "name": f"Vulhub - {cve_id}",
            "url": "https://github.com/vulhub/vulhub",
            "setup": vulhub_str
        })

    # GitHub
    all_results.extend(search_github_docker(cve_id))
    # Docker Hub
    all_results.extend(search_dockerhub(cve_id))
    # Additional sources
    all_results.extend(search_additional_docker_sources(cve_id))

    # Deduplicate by URL
    seen = set()
    unique = []
    for r in all_results:
        if r["url"] not in seen:
            seen.add(r["url"])
            unique.append(r)
    return unique

# ------------------ (Optional) Replace original Docker search with enhanced version ------------------
# If you want the existing `search_pre_built_vulnerable_docker_environments` to return
# a combined string of all found Docker labs, you can uncomment the following:
#
# def search_pre_built_vulnerable_docker_environments(cve_id):
#     labs = search_all_docker_labs(cve_id)
#     if not labs:
#         return "N/A"
#     output = "Found the following Docker-based vulnerable environments:\n\n"
#     for lab in labs:
#         output += f"[bold]{lab['source']}[/bold] – {lab['name']}\n"
#         output += f"  Setup: {lab['setup']}\n\n"
#     return output
