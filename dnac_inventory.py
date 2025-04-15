import os
import aiohttp
import asyncio
import urllib3

urllib3.disable_warnings()

DNAC_HOST = os.environ["DNAC_HOST"]
DNAC_USER = os.environ["DNAC_USER"]
DNAC_PASS = os.environ["DNAC_PASS"]

async def get_dnac_token():
    url = f"{DNAC_HOST}/dna/system/api/v1/auth/token"
    async with aiohttp.ClientSession() as session:
        async with session.post(url, auth=aiohttp.BasicAuth(DNAC_USER, DNAC_PASS), ssl=False) as resp:
            data = await resp.json()
            return data["Token"]

async def get_all_devices(token):
    url = f"{DNAC_HOST}/dna/intent/api/v1/network-device"
    headers = {"X-Auth-Token": token}
    async with aiohttp.ClientSession() as session:
        async with session.get(url, headers=headers, ssl=False) as resp:
            data = await resp.json()
            return data.get("response", [])

async def fetch_config(session, token, device):
    url = f"{DNAC_HOST}/dna/intent/api/v1/network-device/{device['id']}/config"
    headers = {"X-Auth-Token": token}
    try:
        async with session.get(url, headers=headers, ssl=False) as resp:
            config_text = await resp.text()
            return {
                "hostname": device.get("hostname"),
                "platformId": device.get("platformId"),
                "softwareVersion": device.get("softwareVersion"),
                "managementIpAddress": device.get("managementIpAddress"),
                "serialNumber": device.get("serialNumber"),
                "config": config_text.lower()  # normalize for searching
            }
    except Exception as e:
        print(f"Error fetching config for {device['hostname']}: {e}")
        return device

async def fetch_all_configs(devices, token):
    async with aiohttp.ClientSession() as session:
        tasks = [fetch_config(session, token, d) for d in devices]
        return await asyncio.gather(*tasks)

async def load_inventory_from_dnac():
    token = await get_dnac_token()
    devices = await get_all_devices(token)
    print(f"✅ Retrieved {len(devices)} devices")
    inventory = await fetch_all_configs(devices, token)
    return inventory
