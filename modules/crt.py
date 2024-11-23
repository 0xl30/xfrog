# /modules/crtsh.py
import requests

def crtsh_subdomain_module(domain):
    """
    Fetch subdomains for the given domain using crt.sh's database.
    """
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        response = requests.get(url)
        response.raise_for_status()
        subdomains = {entry['name_value'] for entry in response.json()}
        return list(subdomains)
    except requests.exceptions.RequestException as e:
        print(f"[!] crt.sh API request failed: {e}")
        return []
