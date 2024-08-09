import argparse
import time
import requests
from aquilax.client import APIClient
from aquilax.logger import logger

def main():
    parser = argparse.ArgumentParser(description="Aquilax API Client")

    subparsers = parser.add_subparsers(dest='command', help="Available commands")

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
    group_parser.add_argument('--org-id', required=True, help='Organization ID')
    group_parser.add_argument('--name', required=True, help='Name of the group')
    group_parser.add_argument('--description', default='To test all the prod apps', help='Description of the group')
    group_parser.add_argument('--tags', nargs='+', default=['scan', 'aqilax'], help='Tags for the group')

    # Scan command
    scan_parser = subparsers.add_parser('scan', help='Start a scan')
    scan_parser.add_argument('--org-id', required=True, help='Organization ID')
    scan_parser.add_argument('--group-id', required=True, help='Group ID')
    scan_parser.add_argument('--git-uri', required=True, help='Git repository URI')
    scan_parser.add_argument('--scanners', nargs='+', default=['pii_scanner'], help='Scanners to use')
    scan_parser.add_argument('--public', type=bool, default=True, help='Set scan visibility to public')
    scan_parser.add_argument('--frequency', default='Once', help='Scan frequency')
    scan_parser.add_argument('--tags', nargs='+', default=['github', 'abheysharmSEDq', 'django'], help='Tags for the scan')

    # Get Scan Details command
    get_scan_details_parser = subparsers.add_parser('get-scan-details', help='Get scan details')
    get_scan_details_parser.add_argument('--org-id', required=True, help='Organization ID')
    get_scan_details_parser.add_argument('--group-id', required=True, help='Group ID')
    get_scan_details_parser.add_argument('--project-id', required=True, help='Project ID')
    get_scan_details_parser.add_argument('--scan-id', required=True, help='Scan ID')

    args = parser.parse_args()

    client = APIClient()

    try:
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
            logger.info(f"Scan Started: {scan_response}")

        elif args.command == 'get-scan-details':
            # Get Scan Details
            scan_details = client.get_scan_by_id(args.org_id, args.group_id, args.project_id, args.scan_id)
            logger.info(f"Scan Details: {scan_details}")

    except Exception as e:
        logger.error(f"Error occurred: {str(e)}")

if __name__ == "__main__":
    main()
