import requests
from utils import safe_get_json

def certspotter_subdomain_module(domain, api_key=None):
    url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
    headers = {}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    try:
        response = requests.get(url, headers=headers, timeout=10)
        data = safe_get_json(response, "CertSpotter")
        if not data:
            return []

        subdomains = set()
        for entry in data:
            for name in entry.get("dns_names", []):
                if name.endswith(domain):
                    subdomains.add(name.replace("*.", ""))
        return list(subdomains)

    except requests.exceptions.RequestException as e:
        print(f"[!] CertSpotter network error: {e}")
        return []
