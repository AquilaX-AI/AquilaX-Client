import requests
from .config import ClientConfig
from .logger import logger
import json
import os

CONFIG_PATH = os.path.expanduser("~/.aquilax/config.json")

def load_config():
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, 'r') as f:
            return json.load(f)
    return {}

def save_config(config):
    os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
    with open(CONFIG_PATH, 'w') as f:
        json.dump(config, f, indent=4)

class APIClient:
    def __init__(self):
        config = load_config()
        
        if config.get('baseUrl'):
            self.base_url = f"{config.get('baseUrl').rstrip('/')}{ClientConfig.get('baseApiPath')}"
        else:
            self.base_url = f"{ClientConfig.get('baseUrl').rstrip('/')}{ClientConfig.get('baseApiPath')}"

        self.api_token = config.get('apiToken') or os.getenv('AQUILAX_AUTH')

        if not self.api_token:
            self.suggest_token_setup()
            raise ValueError('API Token is required.')
        
        self.headers = {
            'X-AX-Key': f"{self.api_token}",
        }

        self.verify_host = False

        if self.base_url.startswith("https://aquilax.ai"):
            self.verify_host = True


    def suggest_token_setup(self):
            print("API Token is not set or is invalid.")
            print("Please run 'aquilax login <token>' to set your API token.")
            print("If you don't have an API token, please visit https://aquilax.ai to generate one.")

    def start_scan(self, org_id, group_id, git_uri, branch):
        data = {
            'git_uri': git_uri,
            'branch': branch,
            'initiated': "cli"
        }
        headers = self.headers.copy()
        headers['Content-Type'] = 'application/json'

        response = requests.post(f"{self.base_url}/v2/scan?org={org_id}&group={group_id}", headers=headers, json=data, verify=self.verify_host)
        response.raise_for_status()
        return response.json()

    def get_scan_by_id(self, org_id, group_id, scan_id):
        headers = self.headers.copy()
        response = requests.get(f"{self.base_url}/v2/scan/{scan_id}?org={org_id}&group={group_id}", headers=headers, verify=self.verify_host)
        response.raise_for_status()
        return response.json()
    
    def get_scan_results_sarif(self, org_id, group_id, scan_id):
        headers = self.headers.copy()
        headers['Content-Type'] = 'application/json'
        response = requests.get(f"{self.base_url}/v2/scan/{scan_id}?format=sarif&org={org_id}&group={group_id}", headers=headers, verify=self.verify_host)
        response.raise_for_status()
        return response.json()

    def get_all_orgs(self):
        headers = self.headers.copy()
        response = requests.get(f"{self.base_url}/v2/profile", headers=headers, verify=self.verify_host)
        response.raise_for_status()
        profile_data = response.json()
        # Assuming profile returns a list of orgs under 'organizations' key; adjust based on actual API response
        return {'orgs': profile_data.get('organizations', [])}

    def get_group_policy(self, org_id, group_id):
        headers = self.headers.copy()
        response = requests.get(f"{self.base_url}/v2/organization/{org_id}/groups", headers=headers, verify=self.verify_host)
        response.raise_for_status()
        groups_data = response.json()
        for group in groups_data:
            if group.get('_id') == group_id:
                return group.get('security_policy', {}).get('threshold', {})
        return {}