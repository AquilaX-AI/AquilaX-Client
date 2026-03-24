import requests
from .config import ClientConfig
from .logger import logger
import json
import os
import re
import time

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

def normalize_azure_url(git_uri):
    """
    Normalize Azure DevOps URLs by removing embedded usernames.
    
    Converts:
        https://username@dev.azure.com/org/project/_git/repo
    To:
        https://dev.azure.com/org/project/_git/repo
    
    Args:
        git_uri: The Git URI to normalize
        
    Returns:
        Normalized Git URI
    """
    # Pattern to match Azure DevOps URLs with embedded username
    # Matches: https://username@dev.azure.com/...
    azure_pattern = r'(https?://)([^@]+)@(dev\.azure\.com/.+)'
    
    match = re.match(azure_pattern, git_uri)
    if match:
        # Reconstruct URL without the username
        normalized_url = f"{match.group(1)}{match.group(3)}"
        logger.info(f"Normalized Azure URL: {git_uri} -> {normalized_url}")
        return normalized_url
    
    return git_uri

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
        # Normalize Azure DevOps URLs (remove embedded username)
        normalized_git_uri = normalize_azure_url(git_uri)
        
        data = {
            'git_uri': normalized_git_uri,
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

    def scan_code(self, org_id, group_id, code, poll_interval=2, timeout=120):
        headers = self.headers.copy()
        headers['Content-Type'] = 'application/json'
        response = requests.post(
            f"{self.base_url}/v2/code/scan?org={org_id}&group={group_id}",
            headers=headers,
            json={'code': '\n'.join(f'{i+1}. {line}' for i, line in enumerate(code.splitlines()))},
            verify=self.verify_host
        )
        response.raise_for_status()
        scan_id = response.json().get('scan_id')

        elapsed = 0
        while elapsed < timeout:
            result = self._get_code_scan_result(org_id, group_id, scan_id)
            status = result.get('status', '')
            if status == 'COMPLETED':
                return self._normalize_code_findings(result.get('findings', []))
            if status == 'FAILED':
                raise RuntimeError(f"Code scan failed: {result.get('status_message', 'unknown error')}")
            time.sleep(poll_interval)
            elapsed += poll_interval

        raise TimeoutError(f"Code scan {scan_id} did not complete within {timeout}s")

    def _get_code_scan_result(self, org_id, group_id, scan_id):
        headers = self.headers.copy()
        response = requests.get(
            f"{self.base_url}/v2/code/scan/{scan_id}?org={org_id}&group={group_id}",
            headers=headers,
            verify=self.verify_host
        )
        response.raise_for_status()
        return response.json()

    def _normalize_code_findings(self, findings):
        for f in findings:
            if 'line_start' in f:
                f.setdefault('affected_code_line_start', f['line_start'])
            if 'line_end' in f:
                f.setdefault('affected_code_line_end', f['line_end'])
            if 'confidence' in f and 'severity' not in f:
                f['severity'] = f['confidence']
        return findings

    def ai_prompt(self, org_id, group_id, user_prompt, system_prompt=None):
        headers = self.headers.copy()
        headers['Content-Type'] = 'application/json'
        data = {'user_prompt': user_prompt}
        if system_prompt:
            data['system_prompt'] = system_prompt
        response = requests.post(
            f"{self.base_url}/v2/ai/prompt?org={org_id}&group={group_id}",
            headers=headers,
            json=data,
            verify=self.verify_host
        )
        response.raise_for_status()
        return response.json()

    def get_group_policy(self, org_id, group_id):
        headers = self.headers.copy()
        response = requests.get(f"{self.base_url}/v2/organization/{org_id}/groups", headers=headers, verify=self.verify_host)
        response.raise_for_status()
        groups_data = response.json()
        for group in groups_data:
            if group.get('_id') == group_id:
                return group.get('security_policy', {}).get('threshold', {})
        return {}