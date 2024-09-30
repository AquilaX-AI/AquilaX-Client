import argparse
import sys
import json
import requests
from aquilax.client import APIClient
from .config import ClientConfig
from aquilax.logger import logger
import os
from tabulate import tabulate
import time
import colorama
from colorama import Fore, Style

colorama.init(autoreset=True)
CONFIG_PATH = os.path.expanduser("~/.aquilax/config.json")

def load_config():
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, 'r') as f:
            return json.load(f)
    return {}

def show_loading_indicator(loading_index):
    loading_chars = ['|', '/', '-', '\\']
    return loading_chars[loading_index % len(loading_chars)]

def clear_console():
    if os.name == 'nt':
        os.system('cls')
    else:
        os.system('clear')

def color_severity(severity):
    severity = severity.upper()
    if severity == 'CRITICAL':
        return f"{Fore.RED}{severity}{Style.RESET_ALL}"
    elif severity == 'HIGH':
        return f"{Fore.LIGHTRED_EX}{severity}{Style.RESET_ALL}"
    elif severity == 'MEDIUM':
        return f"{Fore.YELLOW}{severity}{Style.RESET_ALL}"
    elif severity == 'LOW':
        return f"{Fore.GREEN}{severity}{Style.RESET_ALL}"
    elif severity == 'WARNING':
        return f"{Fore.CYAN}{severity}{Style.RESET_ALL}"
    elif severity == 'ERROR':
        return f"{Fore.MAGENTA}{severity}{Style.RESET_ALL}"
    elif severity == 'UNKNOWN':
        return f"{Fore.LIGHTBLACK_EX}{severity}{Style.RESET_ALL}"
    else:
        return severity 
    
def print_status_and_findings(status, findings, loading_index):
    clear_console()
    print(f"Scan Status: {status} {show_loading_indicator(loading_index)}")
    if findings:
        colored_findings = [
            (
                scanner,
                path,
                vulnerability,
                color_severity(severity)
            ) for scanner, path, vulnerability, severity in findings
        ]
        table = tabulate(
            colored_findings,
            headers=["Scanner", "Path", "Vulnerability", "Severity"],
            tablefmt="grid"
        )
        print(f"\nFindings:\n{table}")


def save_config(config):
    os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
    with open(CONFIG_PATH, 'w') as f:
        json.dump(config, f, indent=4)

def get_version():
    try:
        version = "1.1.27"
        return version
    except Exception as e:
        logger.error(f"Failed to get the version")
        return "Unknown"

def main():
    parser = argparse.ArgumentParser(description="Aquilax API Client")

    config = load_config()

    # Get the version from the VERSION file
    version = get_version()
    parser.add_argument('-v', '--version', action='version', version=f'Aquilax Client {version}', help="aquilax version check")

    subparsers = parser.add_subparsers(dest='command', help="Available commands")

    # set org and group ID
    parser.add_argument('--set-org', help="Set and save default organization ID")
    parser.add_argument('--set-group', help="Set and save default group ID")

    # Pull command
    pull_parser = subparsers.add_parser('pull', help='Fetch scan by scan_id')
    pull_parser.add_argument('scan_id', help='Scan ID to pull')
    pull_parser.add_argument('--org-id', help='Organization ID (optional, if not provided, the default org ID will be used)')
    pull_parser.add_argument('--format', choices=['json', 'table', 'sarif'], default='table', help='Output format: json, sarif, or table')

    # Organization command
    org_parser = subparsers.add_parser('org', help='Create an organization')
    org_parser.add_argument('--name', required=True, help='Name of the organization')
    org_parser.add_argument('--description', default='Security Scanning', help='Description of the organization')
    org_parser.add_argument('--business-name', default='Technologies', help='Business name of the organization')
    org_parser.add_argument('--website', default='yourwebsite.com', help='Website of the organization')
    org_parser.add_argument('--org-pic', default=None, help='Organization picture URL')
    org_parser.add_argument('--usage', default='Business', help='Usage type of the organization')

    # Group command
    group_parser = subparsers.add_parser('group', help='Create a group')
    group_parser.add_argument('--org-id', default=config.get('org_id'), help='Organization ID')
    group_parser.add_argument('--name', required=True, help='Name of the group')
    group_parser.add_argument('--description', default='To test all the prod apps', help='Description of the group')
    group_parser.add_argument('--tags', nargs='+', default=['scan', 'aquilax'], help='Tags for the group')

    # Scan command
    scan_parser = subparsers.add_parser('scan', help='Start a scan with Git URI')
    scan_parser.add_argument('git', help='Git repository URI')
    scan_parser.add_argument('--scanners', nargs='+', default=['pii_scanner', 'secret_scanner', "iac_scanner", "sast_scanner", "sca_scanner", "container_scanner", "image_scanner", "cicd_scanner"], help='Scanners to use')
    scan_parser.add_argument('--public', type=bool, default=True, help='Set scan visibility to public')
    scan_parser.add_argument('--frequency', default='Once', help='Scan frequency')
    scan_parser.add_argument('--tags', nargs='+', default=['aquilax', 'cli', 'tool'], help='Tags for the scan')
    scan_parser.add_argument('--format', choices=['json', 'table'], default='table', help='Output format: json or table')
    scan_parser.add_argument('--sync', action='store_true', help="Enable sync mode to fetch scan results periodically")

    get_parser = subparsers.add_parser('get', help='Get information')
    get_subparsers = get_parser.add_subparsers(dest='get_command')

    get_orgs_parser = get_subparsers.add_parser('orgs', help='Get all organizations')

    get_scan_details_parser = get_subparsers.add_parser('scan-details', help='Get scan details')
    get_scan_details_parser.add_argument('--org-id', help='Organization ID')
    get_scan_details_parser.add_argument('--group-id', help='Group ID')
    get_scan_details_parser.add_argument('--project-id', required=True, help='Project ID')
    get_scan_details_parser.add_argument('--scan-id', required=True, help='Scan ID')
    get_scan_details_parser.add_argument('--format', choices=['json', 'sarif', 'table'], default='table', help='Output format: json, sarif, or table')

    # Get All Organizations command
    get_groups_parser = get_subparsers.add_parser('groups', help='Get all groups for an organization')
    get_groups_parser.add_argument('--org-id', default=config.get('org_id'), help='Organization ID')

    # Get All Scans command
    get_scans_parser = get_subparsers.add_parser('scans', help='Get all scans for an organization')
    get_scans_parser.add_argument('--org-id', help='Organization ID')
    get_scans_parser.add_argument('--page', type=int, default=1, help='Page number to retrieve (default is 1)')

    # Add the login command
    login_parser = subparsers.add_parser('login', help='Login to Aquilax by setting the API token')
    login_parser.add_argument('token', help='API Token for authentication')

    logout_parser = subparsers.add_parser('logout', help='Logout and remove the API token')

    args = parser.parse_args()

    if args.command == 'login':
        config['apiToken'] = args.token
        save_config(config)
        print(f"Authenticated successfully! \n")
        return

    if args.command == 'logout':
        config.pop('apiToken', None)
        save_config(config)
        print("Logged out!. \n")
        return
    
    if args.command == 'pull':
        client = APIClient()

        org_id = args.org_id or config.get('org_id')

        if not org_id:
            print(f"Organization ID is required but not provided and no default is set.")
            return

        try:
            scan_details = client.get_scan_by_scan_id(org_id, args.scan_id)

            if not scan_details or "scan" not in scan_details:
                print("No scan details found.")
                return

            output_format = getattr(args, 'format', 'table')

            if output_format == 'sarif':
                base_url = ClientConfig.get('baseUrl').rstrip('/')
                base_api_path = ClientConfig.get('baseApiPath').rstrip('/')
                
                sarif_url = f"{base_url}{base_api_path}/organization/{org_id}/scan/{args.scan_id}?format=sarif"
                
                headers = {
                    'X-AX-Key': client.api_token,
                    'Content-Type': 'application/json'
                }
                
                sarif_response = requests.get(sarif_url, headers=headers)
                sarif_response.raise_for_status()

                print(json.dumps(sarif_response.json(), indent=4))

            elif output_format == 'json':
                print(json.dumps(scan_details, indent=4))

            else:
                print("\nScan Details:")
                scan_info = scan_details.get("scan", {})
                results = scan_info.get("results", [])
                table_data = [
                    ["Scan ID", args.scan_id],
                    ["Git URI", scan_info.get('git_uri')],
                    ["Branch", scan_info.get('branch')],
                    ["Scanners", ", ".join([scanner for scanner, used in scan_info.get('scanners', {}).items() if used])]
                ]
                table = tabulate(table_data, headers=["Detail", "Value"], tablefmt="grid")
                print(table)

                if results:
                    all_findings = []
                    for result in results:
                        scanner_name = result.get('scanner', 'N/A')
                        findings = result.get('findings', [])
                        for finding in findings:
                            all_findings.append([
                                scanner_name,
                                finding.get('path', 'N/A'),
                                finding.get('vuln', 'N/A'),
                                finding.get('severity', 'N/A')
                            ])
                    findings_table = tabulate(
                        all_findings,
                        headers=["Scanner", "Path", "Vulnerability", "Severity"],
                        tablefmt="grid"
                    )
                    print(f"\nFindings:\n{findings_table}")

        except requests.HTTPError as http_err:
            logger.error(f"HTTP error occurred: {http_err}")
            print(f"\nResponse: {http_err.response.text}")
        except Exception as e:
            logger.error(f"Error occurred: {str(e)}")

    if args.set_org:
        config['org_id'] = args.set_org
        save_config(config)
        print(f"Default Organization ID set to '{args.set_org}' and saved.")
        return

    if args.set_group:
        config['group_id'] = args.set_group
        save_config(config)
        print(f"Default Group ID set to '{args.set_group}' and saved.")
        return

    if not args.command:
        parser.print_help()
        return

    try:
        client = APIClient()

        if args.command == 'org':
            # Create Organization
            org_response = client.create_organization(
                args.name, args.description, args.business_name, args.website, args.org_pic, args.usage
            )
            org_id = org_response.get('org_id')
            logger.info(f"Organization Created: {org_response}")

        elif args.command == 'group':
            # Create Group
            group_response = client.create_group(
                args.org_id, args.name, args.description, args.tags
            )
            group_id = group_response.get('group').get('_id')
            logger.info(f"Group Created: {group_response}")

        elif args.command == 'scan':
            org_id = config.get('org_id')
            group_id = config.get('group_id')

            if not org_id:
                print("Organization ID is not set. Please set it using --set-org <org_id>.")
                return

            if not group_id:
                print("Group ID is not set. Please set it using --set-group <group_id>.")
                return

            # Start Scan
            scan_response = client.start_scan(
                org_id, group_id, args.git, {scanner: True for scanner in args.scanners}, args.public, args.frequency, args.tags
            )
            scan_id = scan_response.get('scan_id')
            project_id = scan_response.get('project_id')

            if scan_id and project_id:
                scan_data = [
                    ["Scan ID", scan_id],
                    ["Project ID", project_id],
                    ["Git URI", args.git],
                    ["Frequency", args.frequency],
                    ["Tags", ", ".join(args.tags)],
                    ["Scanners", ", ".join([scanner for scanner in args.scanners])]
                ]

                table = tabulate(scan_data, headers=["Detail", "Value"], tablefmt="grid")
                print(f"\nScanning Started:\n{table}")

                if args.sync:
                    print("\nSync mode enabled...\n")
                    current_findings = set()
                    loading_index = 0

                    while True:
                        time.sleep(0.5)

                        try:
                            scan_details = client.get_scan_by_id(org_id, group_id, project_id, scan_id)
                        except requests.HTTPError as http_err:
                            logger.error(f"HTTP error occurred: {http_err}")
                            print(f"\nResponse: {http_err.response.text}")
                            break
                        except Exception as e:
                            logger.error(f"Error occurred: {str(e)}")
                            break

                        status = scan_details.get('scan', {}).get('status', 'N/A')
                        results = scan_details.get('scan', {}).get('results', [])
                        new_findings = []

                        for result in results:
                            scanner_name = result.get('scanner', 'N/A')
                            findings_list = result.get('findings', [])

                            for finding in findings_list:
                                finding_entry = (
                                    scanner_name,
                                    finding.get('path', 'N/A'),
                                    finding.get('vuln', 'N/A'),
                                    finding.get('severity', 'N/A')
                                )
                                if finding_entry not in current_findings:
                                    current_findings.add(finding_entry)
                                    new_findings.append(finding_entry)

                        # Updateing status and findings
                        print_status_and_findings(status, list(current_findings), loading_index)

                        loading_index += 1

                        if status in ['COMPLETED', 'FAILED']:
                            if current_findings:
                                print(f"\nScan Status: {status}")
                                print(f"{Fore.YELLOW}Total Vulnerabilities Found: {len(current_findings)}{Style.RESET_ALL}")
                            else:
                                print(f"\nScan Status: {status}")
                                print(f"{Fore.GREEN}No Vulns Found{Style.RESET_ALL}")
                            break

            else:
                print("Unable to start the scan.")

        elif args.command == 'get':
            if args.get_command == 'orgs':
                # Get all organizations
                orgs_response = client.get_all_orgs()

                if not orgs_response.get('orgs', []):
                    print("No organizations found.")
                    return

                orgs_table_data = []
                for org in orgs_response.get('orgs', []):
                    org_id = org.get('_id')
                    org_name = org.get('name').strip()
                    orgs_table_data.append([org_name, org_id])

                table = tabulate(orgs_table_data, headers=["Organization Name", "Organization ID"], tablefmt="grid")
                print("\nOrganizations List:")
                print(table)
                print("\n\n")

            elif args.get_command == 'scan-details':
                config = load_config()
                org_id = args.org_id or config.get('org_id')
                group_id = args.group_id or config.get('group_id')

                if not org_id or not group_id:
                    print("Organization ID and Group ID must be provided or set as default in config.")
                    return

                # Get Scan Details
                scan_details = client.get_scan_by_id(org_id, group_id, args.project_id, args.scan_id)

                if not scan_details or "scan" not in scan_details:
                    print("No scan details found.")
                    return

                scan_info = scan_details.get("scan", {})
                results = scan_info.get("results", [])
                output_format = args.format or "table"

                if output_format == "json":
                    print(json.dumps(scan_details, indent=4))

                elif output_format == "sarif":
                    base_url = ClientConfig.get('baseUrl').rstrip('/')
                    base_api_path = ClientConfig.get('baseApiPath').rstrip('/')

                    sarif_url = f"{base_url}{base_api_path}/organization/{org_id}/group/{group_id}/project/{args.project_id}/scan/{args.scan_id}?format=sarif"

                    headers = {
                        'X-AX-Key': client.api_token,
                        'Content-Type': 'application/json'
                    }

                    sarif_response = requests.get(sarif_url, headers=headers)
                    sarif_response.raise_for_status()

                    print(json.dumps(sarif_response.json(), indent=4))

                else:
                    print("\n")
                    print(f"Git URI: {scan_info.get('git_uri')}")
                    print(f"Branch: {scan_info.get('branch')}")
                    print(f"Scanners Used: {', '.join([scanner for scanner, used in scan_info.get('scanners', {}).items() if used])}")
                    print("\nResults:")

                    if not results:
                        print("No findings for this scan.")
                        return

                    all_findings = []
                    for result in results:
                        scanner_name = result.get('scanner', 'N/A')
                        findings = result.get('findings', [])
                        for finding in findings:
                            all_findings.append([
                                scanner_name,
                                finding.get('path', 'N/A'),
                                finding.get('vuln', 'N/A'),
                                finding.get('severity', 'N/A')
                            ])

                    if not all_findings:
                        print("No findings across all scanners.")
                        return

                    table = tabulate(
                        all_findings,
                        headers=["Scanner", "Path", "Vulnerability", "Severity"],
                        tablefmt="grid"
                    )
                    print(table)

            elif args.get_command == 'groups':
                groups_response = client.get_all_groups(args.org_id)
                groups = groups_response.get('groups', [])

                if not groups:
                    print("No groups found for this organization.")
                    return

                groups_table_data = []
                for group in groups:
                    group_name = group.get('name', 'N/A')
                    group_id = group.get('_id', 'N/A')
                    description = group.get('description', 'N/A')
                    tags = ', '.join(group.get('tags', []))
                    groups_table_data.append([group_name, group_id, description, tags])

                table = tabulate(groups_table_data, headers=["Group Name", "Group ID", "Description", "Tags"], tablefmt="grid")
                print(f"\nGroups List for Organization ID: {args.org_id}")
                print(table)
                print("\n\n")

            elif args.get_command == 'scans':
                org_id = args.org_id or config.get('org_id')
                if not org_id:
                    print("Organization ID is required but not provided, and no default is set in the config.")
                    return

                scans_response = client.get_all_scans(org_id, page=args.page)
                scans = scans_response

                if not scans:
                    print(f"No scans found for organization ID '{org_id}'.")
                    return

                scans_table_data = []
                for scan in scans:
                    scan_id = scan.get('_id', 'N/A')
                    group_id = scan.get('group', 'N/A')
                    git_uri = scan.get('git_uri', 'N/A')
                    status = scan.get('status', 'N/A')
                    scans_table_data.append([scan_id, group_id, git_uri, status])

                table = tabulate(scans_table_data, headers=["Scan ID", "Group ID", "Git URI", "Status"], tablefmt="grid")
                print(f"\nScans List for Organization ID: {org_id}")
                print(table)
                print("\n\n")

    except ValueError as ve:
        print(ve)

    except Exception as e:
        logger.error(f"Error occurred: {str(e)}")

if __name__ == "__main__":
    main()