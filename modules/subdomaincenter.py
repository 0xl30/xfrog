import requests
from utils import safe_get_json

def subdomaincenter_subdomain_module(domain):
    url = f"https://api.subdomain.center/?domain={domain}"
    try:
        response = requests.get(url, timeout=10)
        data = safe_get_json(response, "SubdomainCenter")
        if not data:
            return []

        if isinstance(data, list):
            return [d.replace("*.", "") for d in data if d.endswith(domain)]
        return [d.replace("*.", "") for d in data.get("subdomains", []) if d.endswith(domain)]

    except requests.exceptions.RequestException as e:
        print(f"[!] SubdomainCenter network error: {e}")
        return []
