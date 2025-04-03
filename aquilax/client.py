import requests
from requests_toolbelt.multipart.encoder import MultipartEncoder
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
        self.base_url = f"{ClientConfig.get('baseUrl').rstrip('/')}{ClientConfig.get('baseApiPath')}"
        self.api_token = config.get('apiToken') or os.getenv('AQUILAX_AUTH')
        if not self.api_token:
            self.suggest_token_setup()
            raise ValueError('API Token is required.')
        self.headers = {
            'X-AX-Key': f"{self.api_token}",
        }

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

        response = requests.post(f"{self.base_url}/v2/scan?org={org_id}&group={group_id}", headers=headers, json=data)
        response.raise_for_status()
        return response.json()

    def start_file_scan(self, org_id, group_id, file_path, scanners, tags):
        fields = {
            'scanners': json.dumps(scanners),
            'tags': json.dumps(tags),
            'file': (os.path.basename(file_path), open(file_path, 'rb'), 'application/zip')
        }
        m = MultipartEncoder(fields=fields)
        headers = self.headers.copy()
        headers['Content-Type'] = m.content_type
        url = f"{self.base_url}/v1/organization/{org_id}/group/{group_id}/file-scan"
        response = requests.post(url, headers=headers, data=m)
        response.raise_for_status()
        return response.json()

    def get_scan_by_id(self, org_id, group_id, scan_id):
        headers = self.headers.copy()
        response = requests.get(f"{self.base_url}/v2/scan/{scan_id}?org={org_id}&group={group_id}", headers=headers)
        response.raise_for_status()
        return response.json()
    
    def get_scan_results_sarif(self, org_id, scan_id):
        headers = self.headers.copy()
        headers['Content-Type'] = 'application/json'
        response = requests.get(f"{self.base_url}/v1/organization/{org_id}/scan/{scan_id}?format=sarif", headers=headers)
        response.raise_for_status()
        return response.json()
    
    def get_executive_summary(self, org_id, scan_id):
        headers = self.headers.copy()
        response = requests.get(f"{self.base_url}/v1/organization/{org_id}/scan/{scan_id}/generate_executive_summary", headers=headers)
        response.raise_for_status()
        return response.json()