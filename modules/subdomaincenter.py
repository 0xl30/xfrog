# /modules/subdomaincenter.py
import requests

def subdomaincenter_subdomain_module(domain):
    """
    Fetch subdomains for the given domain using subdomain.center's service.
    """
    url = f"https://api.subdomain.center/?domain={domain}"
    try:
        response = requests.get(url)
        response.raise_for_status()
        
        # Check if the response is a list
        if isinstance(response.json(), list):
            # If response is a list, return it directly as the list of subdomains
            return response.json()
        else:
            # If the response is a dictionary, process it as expected
            return response.json().get("subdomains", [])
    
    except requests.exceptions.RequestException as e:
        print(f"[!] subdomain.center API request failed: {e}")
        return []
