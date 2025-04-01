import requests
from collections import defaultdict

def get_psirt_token(client_id, client_secret):
    """
    Retrieve an OAuth2 token from Cisco PSIRT API for authentication.
    """
    url = "https://id.cisco.com/oauth2/default/v1/token"
    
    headers = {
        "Content-Type": "application/x-www-form-urlencoded"
    }
    data = (
        f"grant_type=client_credentials&"
        f"client_id={client_id}&"
        f"client_secret={client_secret}"
    )

    response = requests.post(url, headers=headers, data=data)

    try:
        return response.json().get("access_token")
    except Exception as e:
        print("Failed to parse token:", e)
        return None

def get_vulns_for_version(version, token):
    """
    Fetch vulnerability advisories for a specific software version from Cisco PSIRT API.
    """
    url = f"https://apix.cisco.com/security/advisories/v2/OSType/iosxe?version={version}"

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json"
    }
    response = requests.get(url, headers=headers)

    if response.status_code != 200:
        return []

    try:
        result = response.json()
        return result.get("advisories", []) if isinstance(result, dict) else result
    except Exception as e:
        print(f"Error parsing JSON: {e}")
        return []

def correlate_vulnerabilities(inventory, token):
    """
    Match devices in the inventory with known vulnerabilities based on their software version.
    """
    version_set = set(device['softwareVersion'] for device in inventory)
    version_to_vulns = defaultdict(list)

    for version in version_set:
        vulns = get_vulns_for_version(version, token)
        version_to_vulns[version] = vulns

    results = []
    for device in inventory:
        version = device['softwareVersion']
        vulns = version_to_vulns.get(version, [])
        results.append({"device": device, "vulnerabilities": vulns})
    return results