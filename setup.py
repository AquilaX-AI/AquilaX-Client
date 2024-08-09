# setup.py
from setuptools import setup, find_packages

setup(
    name='aquilax',
    version='1.0.0',
    packages=find_packages(),
    install_requires=[
        'requests',
        'python-dotenv',
    ],
    entry_points={
        'console_scripts': [
            'aquilax=aquilax.__main__:main',
        ],
    },
)
