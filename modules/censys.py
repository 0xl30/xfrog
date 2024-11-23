import requests
import base64
import time

def censys_subdomain_module(domain, api_id, api_secret, retries=3):
    url = "https://search.censys.io/api/v2/hosts/search"
    query = f"services.tls.certificates.leaf_data.subject_dn:CN={domain}"
    credentials = f"{api_id}:{api_secret}"
    encoded_credentials = base64.b64encode(credentials.encode()).decode()

    headers = {
        "Authorization": f"Basic {encoded_credentials}",
        "Content-Type": "application/json"
    }

    payload = {"q": query, "per_page": 100}
    subdomains = []

    for attempt in range(retries):
        try:
            response = requests.post(url, headers=headers, json=payload)
            if response.status_code == 429:
                print(f"[!] Rate limit exceeded. Retrying in {2 ** attempt} seconds...")
                time.sleep(2 ** attempt)  # Exponential backoff
                continue
            response.raise_for_status()

            for result in response.json().get("result", {}).get("hits", []):
                subdomains.extend(result.get("dns", {}).get("dns_names", []))
            return list(set(subdomains))

        except requests.exceptions.HTTPError as e:
            print(f"[!] Censys API request failed: {e}")
            if response.status_code == 429 and attempt < retries - 1:
                time.sleep(2 ** attempt)  # Retry on rate-limit error
            else:
                return []

        except requests.exceptions.RequestException as e:
            print(f"[!] Network error occurred: {e}")
            return []

    print("[!] Censys API request failed after multiple attempts.")
    return []
