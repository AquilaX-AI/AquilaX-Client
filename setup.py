from setuptools import setup, find_packages
from pathlib import Path

this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text()

setup(
    name='aquilax',
    version='1.0.2',
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
    long_description=long_description,
    long_description_content_type='text/markdown',  
    url="https://github.com/AquilaX-AI/AquilaX-Client", 
    author="Omer",
    author_email="mdomerkhan8000@gmail.com",
   classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: Apache Software License',  
        'Operating System :: OS Independent',
    ],
    license="Apache License 2.0",  
    python_requires='>=3.6',
)
