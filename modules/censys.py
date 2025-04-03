import requests, base64
import time
from utils import safe_get_json

def censys_subdomain_module(domain, api_id, api_secret, retries=3):
    if not api_id or not api_secret:
        raise Exception("Missing API credentials")

    url = "https://search.censys.io/api/v2/hosts/search"
    query = f"services.tls.certificates.leaf_data.subject_dn:CN={domain}"
    credentials = base64.b64encode(f"{api_id}:{api_secret}".encode()).decode()

    headers = {
        "Authorization": f"Basic {credentials}",
        "Content-Type": "application/json"
    }

    payload = {"q": query, "per_page": 100}
    subdomains = set()

    for attempt in range(retries):
        try:
            response = requests.post(url, headers=headers, json=payload, timeout=10)
            if response.status_code == 429:
                print(f"[!] Censys: Rate limited. Retrying...")
                time.sleep(2 ** attempt)
                continue

            data = safe_get_json(response, "Censys")
            if not data:
                return []

            for result in data.get("result", {}).get("hits", []):
                subdomains.update(result.get("dns", {}).get("dns_names", []))
            return list(set(s.replace("*.", "") for s in subdomains if s.endswith(domain)))

        except requests.exceptions.RequestException as e:
            print(f"[!] Censys network error: {e}")
            return []

    print("[!] Censys failed after retries")
    return []
