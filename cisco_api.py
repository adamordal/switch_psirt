import os
import requests
from collections import defaultdict

# ===== PSIRT API Auth =====
def get_psirt_token(client_id, client_secret):
    url = "https://id.cisco.com/oauth2/default/v1/token"
    data = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    response = requests.post(url, data=data, headers=headers)
    return response.json().get("access_token")

# ===== Feature Detection Mapping =====
PSIRT_FEATURE_MAP = {
    "ospf": ["router ospf"],
    "eigrp": ["router eigrp"],
    "bgp": ["router bgp"],
    "rip": ["router rip"],
    "snmp": ["snmp-server"],
    "http": ["ip http", "ip http server"],
    "https": ["ip http secure-server"],
    "webui": ["ip http", "webui"],
    "telnet": ["transport input telnet"],
    "ssh": ["ip ssh", "transport input ssh"],
    "ntp": ["ntp server", "ntp peer"],
    "dhcp": ["ip dhcp pool", "service dhcp"],
    "dns": ["ip name-server"],
    "tftp": ["tftp-server"],
    "ftp": ["ftp-server"],
    "lldp": ["lldp run"],
    "cdp": ["cdp run"],
    "aaa": ["aaa new-model", "radius-server", "tacacs-server"],
    "dot1x": ["dot1x", "authentication port-control"],
    "macsec": ["mka policy", "macsec"],
    "voice": ["voice service voip", "dial-peer", "sip-ua"],
    "vlan": ["vlan", "switchport access vlan"],
    "vxlan": ["vxlan", "nve"],
    "controller": ["ap name", "wlan", "dot11", "mobility anchor"],
    "vpn": ["crypto isakmp", "crypto ipsec", "tunnel protection", "tunnel interface", "vrf"],
    "omp": ["omp", "vpn 0", "vmanage", "vsmart"],
    "ipsec": ["crypto ipsec", "transform-set"],
    "ike": ["crypto ikev2", "isakmp"],
    "sntp": ["sntp server"],
    "netflow": ["ip flow", "flow exporter"],
    "http2": ["ip http2", "http2 enable"]
}

def config_uses_feature(config_text, keywords):
    return any(keyword in config_text for keyword in keywords)

def is_relevant_vulnerability(vuln, config_text):
    feature_key = vuln.get("feature", "").lower()
    if not feature_key:
        return True
    if feature_key not in PSIRT_FEATURE_MAP:
        return True
    keywords = PSIRT_FEATURE_MAP[feature_key]
    return config_uses_feature(config_text, keywords)

def detect_os_type(device):
    os_hint = device.get("softwareType", "").lower()

    if "ios-xe" in os_hint:
        return "iosxe"
    elif "nx-os" in os_hint or "nxos" in os_hint:
        return "nxos"
    elif "asa" in os_hint:
        return "asa"
    elif "ftd" in os_hint or "firepower" in os_hint:
        return "ftd"
    elif "wireless" in os_hint or "wlc" in os_hint:
        return "wlc"
    elif "ios xr" in os_hint:
        return "iosxr"

    platform_id = device.get("platformId", "")
    if not platform_id:
        return "iosxe"

    platform_id = platform_id.lower()
    if "c9" in platform_id or "cat" in platform_id:
        return "iosxe"
    elif "n9" in platform_id:
        return "nxos"
    elif "asa" in platform_id:
        return "asa"
    elif "ftd" in platform_id:
        return "ftd"

    return "iosxe"

def get_vulns_for_version(version, token, os_type="iosxe"):
    url = f"https://apix.cisco.com/security/advisories/v2/OSType/{os_type}?version={version}"
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
    version_cache = {}
    results = []

    for device in inventory:
        version = device.get("softwareVersion")
        os_type = detect_os_type(device)
        print(f"[DEBUG] {device.get('hostname')} ({device.get('platformId')}) → OS Type: {os_type}")

        config_text = device.get("config", "").lower()

        cache_key = (os_type, version)
        if cache_key not in version_cache:
            version_cache[cache_key] = get_vulns_for_version(version, token, os_type=os_type)

        all_advisories = version_cache[cache_key]

        relevant = [
            advisory for advisory in all_advisories
            if is_relevant_vulnerability(advisory, config_text)
        ]

        results.append({
            "device": device,
            "vulnerabilities": relevant
        })

    return results
