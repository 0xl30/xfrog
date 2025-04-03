import requests
from utils import safe_get_json

def virustotal_subdomain_module(domain, api_key):
    if not api_key:
        raise Exception("Missing VirusTotal API key")

    url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains"
    headers = {
        "x-apikey": api_key
    }

    try:
        response = requests.get(url, headers=headers, timeout=10)
        data = safe_get_json(response, "VirusTotal")
        if not data:
            return []

        return [d.get("id", "").replace("*.", "") for d in data.get("data", []) if d.get("id", "").endswith(domain)]

    except requests.exceptions.RequestException as e:
        print(f"[!] VirusTotal network error: {e}")
        return []
