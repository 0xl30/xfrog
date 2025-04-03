# /modules/crt.py
import requests
import time

def crtsh_subdomain_module(domain):
    """
    Fetch subdomains for the given domain using crt.sh's database.
    """
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    headers = {
        "User-Agent": "Mozilla/5.0 (SubdomainScanner)"
    }

    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 503:
            raise Exception("503 Service Unavailable from crt.sh")

        response.raise_for_status()

        try:
            data = response.json()
        except ValueError:
            raise Exception("Invalid JSON returned by crt.sh")

        subdomains = set()
        for entry in data:
            name = entry.get('name_value', '').replace("*.", "").strip()
            if name and name.endswith(domain):
                subdomains.add(name)

        return list(sorted(subdomains))

    except requests.exceptions.Timeout:
        raise Exception("crt.sh request timed out")
    except requests.exceptions.RequestException as e:
        raise Exception(f"crt.sh network error: {str(e)}")
    except Exception as e:
        raise Exception(str(e))
