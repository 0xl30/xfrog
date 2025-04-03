def safe_get_json(response, service_name):
    try:
        response.raise_for_status()
        return response.json()
    except ValueError:
        print(f"[!] {service_name}: Invalid JSON")
    except Exception as e:
        print(f"[!] {service_name} error: {str(e)}")
    return None
