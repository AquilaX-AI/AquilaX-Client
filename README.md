# AquilaX Client

A command-line interface (CLI) tool for interacting with the AquilaX AppSec platform. It allows you to initiate security scans on Git repositories, retrieve scan results, and manage authentication and configuration.

## Features

- Authenticate with AquilaX using API tokens
- Start security scans on Git repositories
- Retrieve scan details and findings
- Support for CI/CD pipelines with failure thresholds
- Sync mode for real-time scan monitoring
- Fetch organizations and groups

## Prerequisites

- Python 3.7 or higher
- `pip` package manager

## Installation

### From PyPI
```bash
pip install aquilax
```

### From Source
```bash
git clone https://github.com/AquilaX-AI/AquilaX-Client.git
cd AquilaX-Client
pip install -e .
```

## Usage

The general command structure is: `aquilax <command> [options]`

### Authentication

#### Login
Authenticate with your AquilaX API token.

```bash
aquilax login <token>
```

For on-premise installations:
```bash
aquilax login <token> --server "https://your-aquilax-server.com"
```

#### Logout
Remove stored authentication credentials.

```bash
aquilax logout
```

### Configuration

Set default organization and group IDs to avoid specifying them in every command.

```bash
aquilax --set-org <org_id>
aquilax --set-group <group_id>
```

### Scanning

#### Start a Scan
Initiate a security scan on a Git repository.

```bash
aquilax scan <git_uri> [--scanners <scanner1> <scanner2>] [--branch <branch>] [--sync]
```

Options:
- `--scanners`: List of scanners (default: pii_scanner, secret_scanner, iac_scanner, sast_scanner, sca_scanner, container_scanner, image_scanner, cicd_scanner)
- `--branch`: Git branch to scan (default: main)
- `--sync`: Enable sync mode to monitor scan progress in real-time

#### CI/CD Scan
Run a scan optimized for CI/CD pipelines with failure thresholds.

```bash
aquilax ci-scan <git_uri> [--org-id <org_id>] [--group-id <group_id>] [--fail-on-vulns] [--branch <branch>] [--sync] [--format <json|table>]
```

Options:
- `--org-id`: Organization ID (uses default if not specified)
- `--group-id`: Group ID (uses default if not specified)
- `--fail-on-vulns`: Exit with error code if vulnerabilities are found
- `--branch`: Git branch to scan (default: main)
- `--sync`: Enable sync mode
- `--format`: Output format (default: table)
- `--output-dir`: Directory to save PDF reports
- `--save-pdf`: Save PDF report locally

### Retrieving Data

#### Pull Scan Results
Fetch details of a completed scan by scan ID.

```bash
aquilax pull <scan_id> [--org-id <org_id>] [--group-id <group_id>] [--format <json|table>]
```

#### Get Organizations
List all organizations accessible to the authenticated user.

```bash
aquilax get orgs
```

#### Get Groups
List all groups within an organization.

```bash
aquilax get groups [--org-id <org_id>]
```

#### Get Scan Details
Retrieve detailed information about a specific scan.

```bash
aquilax get scan-details --scan-id <scan_id> [--org-id <org_id>] [--group-id <group_id>] [--format <json|table>]
```

### Version
Display the client version.

```bash
aquilax --version
```
## Examples

### Basic Scan
```bash
aquilax login your_api_token
aquilax --set-org your_org_id
aquilax --set-group your_group_id
aquilax scan https://github.com/your-org/your-repo --sync
```

### CI/CD Integration
```bash
aquilax ci-scan https://github.com/your-org/your-repo --fail-on-vulns --format json
```

### Retrieve Scan Results
```bash
aquilax pull scan_id_123 --format table
```

## Security Policy Thresholds

The client fetches security policy thresholds from your group's configuration in AquilaX. Scans will fail if vulnerabilities exceed these thresholds (configurable per group for HIGH, MEDIUM, LOW, CRITICAL, total).

## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## Error Handling

The client handles API errors gracefully and provides informative messages. Ensure your API token is valid and you have access to the specified organizations and groups.

## Troubleshooting

- **Module Import Errors**: Ensure the virtual environment is activated and the package is installed.
- **Unauthorized Error**: Verify your API token is correct and has the necessary permissions.
- **Scan Failures**: Check that the Git repository is accessible and the branch exists.
- **Threshold Errors**: Ensure your group has security policy thresholds configured in AquilaX.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For issues and questions:
- 📧 Email: support@aquilax.ai
- 🌐 Website: https://aquilax.ai
