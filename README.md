# Aquilax Python Client

This is a Python client for interacting with the Aquilax API. It allows you to easily manage organizations, groups, initiate scans and to get scan results by making request to the Aquilax server.

## Features

- Create an organization
- Create a group within an organization
- Start a scan on a given Git repository
- Get scan results for a given Git repository


### Prerequisites

- Python 3.7 or higher
- `pip` package manager
 
### Set Up the Environment
Create and activate a virtual environment:

``` bash
python3 -m venv env
source env/bin/activate  # On Windows, use `env\Scripts\activate`
```

### Install Dependencies
Install the required Python packages:
```bash
pip install -e . 
```
## Usage Command Structure and General Usage

To run the client, use the following structure:```aquilax <command> [options]```The Aquilax API Client supports the following commands:- org: Create an organization.- group: Create a group within an organization.- scan: Start a scan for a specific group.- get-scan-details: Retrieve details of a specific scan.

### **Command: org**
> Creates a new organization with specified details.

**Options**: --name (required): The name of the organization.--description (optional, default: "Social Media"): A brief description of the organization.--business-name (optional, default: "MenDoFeel Technologies"): The business name associated with the organization.--website (optional, default: "mendofeel.com"): The organization's website URL.--org-pic (optional, default: a predefined image URL): The URL of the organization's picture.--usage (optional, default: "Business"): The usage type for the organization.

> **Example Usage:**
```bash
aquilax org --name "My Organization" --description "Tech Company" --business-name "TechCorp" --website "techcorp.com" --usage "Business"
```

### **Command: group**
> Creates a new group within an existing organization.

**Options:** --org-id (required): The ID of the organization in which to create the group.--name (required): The name of the group.--description (optional, default: "To test all the prod apps"): A brief description of the group.--tags (optional, default: ['mendofeel', 'abheysharma']): Tags associated with the group.

```bash
aquilax group --org-id "org123" --name "Development Group" --description "Group for devs" --tags "dev" "team"
```

### **Command: scan**
> Starts a scan for a specific group within an organization.

**Options:** --org-id (required): The ID of the organization.--group-id (required): The ID of the group.--git-uri (required): The URI of the Git repository to scan.--scanners (optional, default: ['pii_scanner']): A list of scanners to use.--public (optional, default: True): Whether the scan should be public.--frequency (optional, default: Once): The frequency of the scan (e.g., Once).--tags (optional, default: ['github', 'abheysharmSEDq', 'django']): Tags associated with the scan.

```bash
aquilax scan --org-id "org123" --group-id "group456" --git-uri "https://github.com/user/repo" --scanners "sast_scanner" "iac_scanner" --public True --frequency Once --tags "security" "audit"
```

### **Command: get-scan-details**
> Retrieves the details of a specific scan.

**Options:** --org-id (required): The ID of the organization.--group-id (required): The ID of the group.--project-id (required): The ID of the project.--scan-id (required): The ID of the scan.
```bash
**Example Usage:**aquilax get-scan-details --org-id "org123" --group-id "group456" --project-id "proj789" --scan-id "scan101"
```

## Environment Variable
- You must set the AQUILAX_AUTH environment variable with your Aquilax API token for the client to work.

```bash
export AQUILAX_AUTH=aquilax_api_token_here
```

### Command-Line Arguments
- --orgName: The name of the organization to create.
- --groupName: The name of the group to create within the organization.
- --gitUri: The Git URI of the repository to scan.

## Running the Client for Development
To run the client while developing:

```bash
python -m aquilax
```

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## Error Handling
If the API token is not provided or if any request fails, the client will raise an appropriate error and log the details.

## Troubleshooting
- Module Import Errors: Ensure your environment is activated and the package is installed.
- Unauthorized Error: Ensure the AQUILAX_AUTH environment variable is set correctly.

## Clone the Repository

```bash
git clone https://github.com/AquilaX-AI/AquilaX-Client.git
cd AquilaX-Client
```
