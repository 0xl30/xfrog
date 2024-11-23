# /modules/certspotter.py
import requests

def certspotter_subdomain_module(domain, api_key=None):
    """
    Fetch subdomains for the given domain using Cert Spotter's API.

    :param domain: The domain to search for subdomains.
    :param api_key: Optional API key for Cert Spotter.
    :return: List of subdomains found for the given domain.
    """
    url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
    headers = {}

    # Include API key if provided
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()  # Raise an error for bad status codes

        # Parse the JSON response to collect subdomains
        subdomains = set()
        for entry in response.json():
            dns_names = entry.get("dns_names", [])
            for name in dns_names:
                # Add only subdomains that match the specified domain
                if name.endswith(f".{domain}") or name == domain:
                    subdomains.add(name.replace("*.",""))  # Remove wildcard if present

        return list(subdomains)

    except requests.exceptions.HTTPError as e:
        print(f"[!] Cert Spotter API request failed: {e}")
        return []
    except requests.exceptions.RequestException as e:
        print(f"[!] Network error occurred: {e}")
        return []
