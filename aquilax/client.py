import requests
from requests_toolbelt.multipart.encoder import MultipartEncoder
from .config import ClientConfig
from .logger import logger
import json

class APIClient:
    def __init__(self):
        self.base_url = f"{ClientConfig.get('baseUrl').rstrip('/')}{ClientConfig.get('baseApiPath')}"
        self.api_token = ClientConfig.get('apiToken')
        if not self.api_token:
            self.suggest_token_setup()
            raise ValueError('API Token is required.')
        self.headers = {
            'X-AX-Key': f"{self.api_token}",
        }

    def suggest_token_setup(self):
        print("API Token is not set or is invalid.")
        print("Please ensure you have set the API token in your environment variables as 'export AQUILAX_AUTH'.")
        print("If you don't have an API token, please visit https://app.aquilax.ai to generate one.")

    def create_organization(self, org_name, description, business_name, website, org_pic=None, usage='Business'):
        default_org_pic = "https://i.pinimg.com/236x/a2/c2/64/a2c264977d561691c1ece4921704ae91.jpg"
        
        data = {
            'name': org_name,
            'description': description,
            'business_name': business_name,
            'website': website,
            'org_pic': org_pic if org_pic else default_org_pic,
            'usage': usage,
        }

        m = MultipartEncoder(fields=data)
        headers = self.headers.copy()
        headers['Content-Type'] = m.content_type

        response = requests.post(f"{self.base_url}/organization", headers=headers, data=m)
        response.raise_for_status()
        return response.json()

    def create_group(self, org_id, group_name, description, tags):
        data = {
            'name': group_name,
            'description': description,
            'tags': tags,
        }
        headers = self.headers.copy()
        headers['Content-Type'] = 'application/json'

        response = requests.post(f"{self.base_url}/organization/{org_id}/group", headers=headers, json=data)
        response.raise_for_status()
        return response.json()

    def start_scan(self, org_id, group_id, git_uri, scanners, public, frequency, tags):
        data = {
            'git_uri': git_uri,
            'terms': True,
            'scanners': scanners,
            'public': public,
            'frequency': frequency,
            'tags': tags,
        }
        headers = self.headers.copy()
        headers['Content-Type'] = 'application/json'

        response = requests.post(f"{self.base_url}/organization/{org_id}/group/{group_id}/scan", headers=headers, json=data)
        response.raise_for_status()
        return response.json()

    def get_scan_by_id(self, org_id, group_id, project_id, scan_id):
        headers = self.headers.copy()
        response = requests.get(f"{self.base_url}/organization/{org_id}/group/{group_id}/project/{project_id}/scan/{scan_id}", headers=headers)
        response.raise_for_status()
        return response.json()

    def get_all_orgs(self):
        headers = self.headers.copy()
        response = requests.get(f"{self.base_url}/organization", headers=headers)
        response.raise_for_status()
        return response.json()

    def get_all_groups(self, org_id):
        response = requests.get(f"{self.base_url}/organization/{org_id}/group", headers=self.headers)
        response.raise_for_status()
        return response.json()

    def get_all_scans(self, org_id, page=1):
        headers = self.headers.copy()
        limit = 50
        params = {
            'limit': limit,
            'page': page
        }
        response = requests.get(f"{self.base_url}/organization/{org_id}/scans", headers=headers, params=params)
        response.raise_for_status()
        
        scans_data = response.json()
        return scans_data.get('scans', [])