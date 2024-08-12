import os

class ClientConfig:
    _config = {
        'apiToken': os.getenv('AQUILAX_AUTH', ''),
        'baseUrl': 'https://app.aquilax.ai',
        'baseApiPath': '/api/v1',
    }

    @classmethod
    def get(cls, key):
        return cls._config.get(key, None)

    @classmethod
    def set(cls, config):
        cls._config.update(config)
