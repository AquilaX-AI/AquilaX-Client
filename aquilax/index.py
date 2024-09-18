import argparse
import sys
import json
import requests
from aquilax.client import APIClient
from .config import ClientConfig
from aquilax.logger import logger
import os
from tabulate import tabulate

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

def get_version():
    try:
        version = "1.1.24"
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
    parser.add_argument('--set-org-id', help="Set and save default organization ID")
    parser.add_argument('--set-group-id', help="Set and save default group ID")

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
    scan_parser = subparsers.add_parser('scan', help='Start a scan')
    scan_parser.add_argument('--org-id', default=config.get('org_id'), help='Organization ID')
    scan_parser.add_argument('--group-id', default=config.get('group_id'), help='Group ID')
    scan_parser.add_argument('--git-uri', required=True, help='Git repository URI')
    scan_parser.add_argument('--scanners', nargs='+', default=['pii_scanner'], help='Scanners to use')
    scan_parser.add_argument('--public', type=bool, default=True, help='Set scan visibility to public')
    scan_parser.add_argument('--frequency', default='Once', help='Scan frequency')
    scan_parser.add_argument('--tags', nargs='+', default=['aquilax', 'cli', 'tool'], help='Tags for the scan')
    scan_parser.add_argument('--format', choices=['json', 'table'], default='table', help='Output format: json or table')

    # Get Scan Details command
    get_scan_details_parser = subparsers.add_parser('get-scan-details', help='Get scan details')
    get_scan_details_parser.add_argument('--org-id', help='Organization ID')
    get_scan_details_parser.add_argument('--group-id', help='Group ID')
    get_scan_details_parser.add_argument('--project-id', required=True, help='Project ID')
    get_scan_details_parser.add_argument('--scan-id', required=True, help='Scan ID')
    get_scan_details_parser.add_argument('--format', choices=['json', 'sarif', 'table'], default='table', help='Output format: json, sarif, or table')

    # Get All Organizations command
    get_orgs_parser = subparsers.add_parser('get-orgs', help='Get all organizations')

    # Get All Groups command
    get_groups_parser = subparsers.add_parser('get-groups', help='Get all groups for an organization')
    get_groups_parser.add_argument('--org-id', default=config.get('org_id'), help='Organization ID')

    # Get All Scans command
    get_scans_parser = subparsers.add_parser('get-scans', help='Get all scans for an organization')
    get_scans_parser.add_argument('--org-id', help='Organization ID')
    get_scans_parser.add_argument('--page', type=int, default=1, help='Page number to retrieve (default is 1)')

    args = parser.parse_args()

    if args.set_org_id:
        config['org_id'] = args.set_org_id
        save_config(config)
        print(f"Default Organization ID set to '{args.set_org_id}' and saved.")
        return

    if args.set_group_id:
        config['group_id'] = args.set_group_id
        save_config(config)
        print(f"Default Group ID set to '{args.set_group_id}' and saved.")
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
            # Start Scan
            scan_response = client.start_scan(
                args.org_id, args.group_id, args.git_uri, {scanner: True for scanner in args.scanners}, args.public, args.frequency, args.tags
            )
            scan_id = scan_response.get('scan_id')
            project_id = scan_response.get('project_id')

            if scan_id and project_id:
                if args.format == "json":
                    print(json.dumps(scan_response, indent=4))
                    print('\n')
                else:
                    scan_data = [
                        ["Scan ID", scan_id],
                        ["Project ID", project_id],
                        ["Git URI", args.git_uri],
                        ["Frequency", args.frequency],
                        ["Tags", ", ".join(args.tags)],
                        ["Scanners", ", ".join([scanner for scanner in args.scanners])]
                    ]

                    table = tabulate(
                        scan_data,
                        headers=["Detail", "Value"],
                        tablefmt="grid"
                    )

                    print('\n')
                    print(f"Scanning Started Successfully:")
                    print(table)
                    print('\n')

            else:
                print("Unable to start the scan.")

        elif args.command == 'get-scan-details':
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

        elif args.command == 'get-orgs':
            # Get All Organizations
            orgs_response = client.get_all_orgs()
            
            if not orgs_response.get('orgs', []):
                print("No organizations found.")
                return

            orgs_table_data = []
            for org in orgs_response.get('orgs', []):
                org_id = org.get('_id')
                org_name = org.get('name').strip()
                orgs_table_data.append([org_name, org_id])

            table = tabulate(
                orgs_table_data,
                headers=["Organization Name", "Organization ID"],
                tablefmt="grid"
            )
            print("\nOrganizations List:")
            print(table)
            print("\n\n")

        elif args.command == 'get-groups':
            # Get All Groups
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

            table = tabulate(
                groups_table_data,
                headers=["Group Name", "Group ID", "Description", "Tags"],
                tablefmt="grid"
            )
            print(f"\nGroups List for Organization ID: {args.org_id}")
            print(table)
            print("\n\n")

        elif args.command == 'get-scans':
            # Get All Scans
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

            table = tabulate(
                scans_table_data,
                headers=["Scan ID", "Group ID", "Git URI", "Status"],
                tablefmt="grid"
            )
            print(f"\nScans List for Organization ID: {org_id}")
            print(table)
            print("\n\n")

    except ValueError as ve:
        print(ve)

    except Exception as e:
        logger.error(f"Error occurred: {str(e)}")

if __name__ == "__main__":
    main()