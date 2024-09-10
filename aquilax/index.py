import argparse
import sys
import json
from aquilax.client import APIClient
from aquilax.logger import logger
import os

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
        version = "1.1.19"
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
    org_parser.add_argument('--description', default='Social Media', help='Description of the organization')
    org_parser.add_argument('--business-name', default='MenDoFeel Technologies', help='Business name of the organization')
    org_parser.add_argument('--website', default='mendofeel.com', help='Website of the organization')
    org_parser.add_argument('--org-pic', default=None, help='Organization picture URL')
    org_parser.add_argument('--usage', default='Business', help='Usage type of the organization')

    # Group command
    group_parser = subparsers.add_parser('group', help='Create a group')
    group_parser.add_argument('--org-id', default=config.get('org_id'), help='Organization ID')
    group_parser.add_argument('--name', required=True, help='Name of the group')
    group_parser.add_argument('--description', default='To test all the prod apps', help='Description of the group')
    group_parser.add_argument('--tags', nargs='+', default=['scan', 'aqilax'], help='Tags for the group')

    # Scan command
    scan_parser = subparsers.add_parser('scan', help='Start a scan')
    scan_parser.add_argument('--org-id', default=config.get('org_id'), help='Organization ID')
    scan_parser.add_argument('--group-id', default=config.get('group_id'), help='Group ID')
    scan_parser.add_argument('--git-uri', required=True, help='Git repository URI')
    scan_parser.add_argument('--scanners', nargs='+', default=['pii_scanner'], help='Scanners to use')
    scan_parser.add_argument('--public', type=bool, default=True, help='Set scan visibility to public')
    scan_parser.add_argument('--frequency', default='Once', help='Scan frequency')
    scan_parser.add_argument('--tags', nargs='+', default=['github', 'abheysharmSEDq', 'django'], help='Tags for the scan')
    scan_parser.add_argument('--output-format', default='json', choices=['json', 'sarif'], help='Specify the output format (json or sarif)')

    # Get Scan Details command
    get_scan_details_parser = subparsers.add_parser('get-scan-details', help='Get scan details')
    get_scan_details_parser.add_argument('--org-id', required=True, help='Organization ID')
    get_scan_details_parser.add_argument('--group-id', required=True, help='Group ID')
    get_scan_details_parser.add_argument('--project-id', required=True, help='Project ID')
    get_scan_details_parser.add_argument('--scan-id', required=True, help='Scan ID')
    get_scan_details_parser.add_argument('--output-format', default='json', choices=['json', 'sarif'], help='Specify the output format (json or sarif)')

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
                args.org_id, args.group_id, args.git_uri, {scanner: True for scanner in args.scanners}, args.public, args.frequency, args.tags, args.output_format
            )
            scan_id = scan_response.get('scan_id')
            project_id = scan_response.get('project_id')

            if scan_id and project_id:
                scan_response['scan_id'] = scan_id
                scan_response['project_id'] = project_id

            if args.output_format == 'sarif':
                print(json.dumps(scan_response['sarif'], indent=4))
            else:
                print(json.dumps(scan_response, indent=4))

        elif args.command == 'get-scan-details':
            # Get Scan Details
            scan_details = client.get_scan_by_id(args.org_id, args.group_id, args.project_id, args.scan_id, args.output_format)
            print(scan_details)

        elif args.command == 'get-orgs':
            # Get All Organizations
            orgs_response = client.get_all_orgs()
            
            if not orgs_response.get('orgs', []):
                print("No organizations found.")
                return

            print("\nOrganizations List:")
            print(f"{'Organization Name':<30} {'Organization ID':<40}")
            print("="*70)
            for org in orgs_response.get('orgs', []):
                org_id = org.get('_id')
                org_name = org.get('name').strip()
                print(f"{org_name:<30} {org_id:<40}")
            print("\n\n")

        elif args.command == 'get-groups':
            # Get All Groups
            groups_response = client.get_all_groups(args.org_id)
            groups = groups_response.get('groups', [])
            
            if not groups:
                print("No groups found for this organization.")
                return
            
            print("\nGroups List for Organization ID:", args.org_id)
            print(f"{'Group Name':<20} {'Group ID':<40} {'Description':<30} {'Tags':<20}")
            print("="*110)
            
            for group in groups:
                group_name = group.get('name', 'N/A')
                group_id = group.get('_id', 'N/A')
                description = group.get('description', 'N/A')
                tags = ', '.join(group.get('tags', []))
                
                print(f"{group_name:<20} {group_id:<40} {description:<30} {tags:<20}")
            print("\n\n")

        elif args.command == 'get-scans':
            # Get All Scans
            org_id = args.org_id or config.get('org_id')
            if not org_id:
                print("Error: Organization ID is required but not provided, and no default is set in the config.")
                return
            
            scans_response = client.get_all_scans(org_id, page=args.page)
            scans = scans_response
            
            if not scans:
                print(f"No scans found for organization ID '{org_id}'.")
                return
            
            print(f"\nScans List for Organization ID: {org_id}")
            print(f"{'Scan ID':<20} {'Group ID':<40} {'Git URI':<40} {'Status':<15}")
            print("="*125)
            
            for scan in scans:
                scan_id = scan.get('_id', 'N/A')
                group_id = scan.get('group', 'N/A')
                git_uri = scan.get('git_uri', 'N/A')
                status = scan.get('status', 'N/A')
                
                print(f"{scan_id:<20} {group_id:<40} {git_uri:<40} {status:<15}")
            print("\n\n")

    except ValueError as ve:
        print(ve)

    except Exception as e:
        logger.error(f"Error occurred: {str(e)}")

if __name__ == "__main__":
    main()
