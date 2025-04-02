import os
import json

CONFIG_PATH = os.path.expanduser("~/.aquilax/config.json")

class ClientConfig:
    _config = {
        'apiToken': os.getenv('AQUILAX_AUTH', ''),
        'baseUrl': 'https://aquilax.ai',
        'baseApiPath': '/api',
    }

    @classmethod
    def get(cls, key):
        if os.path.exists(CONFIG_PATH):
            with open(CONFIG_PATH, 'r') as f:
                cls._config.update(json.load(f))
        return cls._config.get(key, None)

    @classmethod
    def set(cls, config):
        cls._config.update(config)
        os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
        with open(CONFIG_PATH, 'w') as f:
            json.dump(cls._config, f, indent=4)

def load_config():
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, 'r') as f:
            return json.load(f)
    return {}

def save_config(config):
    os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
    with open(CONFIG_PATH, 'w') as f:
        json.dump(config, f, indent=4)
