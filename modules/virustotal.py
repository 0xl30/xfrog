# /modules/virustotal.py
import requests

def virustotal_subdomain_module(domain, api_key):
    """
    Fetch subdomains for the given domain using VirusTotal's API.
    """
    url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains"
    headers = {
        "x-apikey": api_key,  # Some older documentation uses "Authorization: Bearer <api_key>", but x-apikey is correct for current usage
    }
    
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()  # Raise an error for bad status codes
        return [entry['id'] for entry in response.json().get("data", [])]
    except requests.exceptions.HTTPError as e:
        print(f"[!] VirusTotal API request failed: {e}")
        return []
    except requests.exceptions.RequestException as e:
        print(f"[!] Network error occurred: {e}")
        return []
