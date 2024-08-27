import argparse
import sys
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

    # Get All Organizations command
    get_orgs_parser = subparsers.add_parser('get-orgs', help='Get all organizations')

    # Get All Groups command
    get_groups_parser = subparsers.add_parser('get-groups', help='Get all groups for an organization')
    get_groups_parser.add_argument('--org-id', required=True, help='Organization ID')

    # Get All Scans command
    get_scans_parser = subparsers.add_parser('get-scans', help='Get all scans for an organization')
    get_scans_parser.add_argument('--org-id', required=True, help='Organization ID')
    get_scans_parser.add_argument('--page', type=int, default=1, help='Page number to retrieve (default is 1)')

    args = parser.parse_args()

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
            logger.info(f"Scan Started: {scan_response}")

        elif args.command == 'get-scan-details':
            # Get Scan Details
            scan_details = client.get_scan_by_id(args.org_id, args.group_id, args.project_id, args.scan_id)
            logger.info(f"Scan Details: {scan_details}")

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
            scans_response = client.get_all_scans(args.org_id, page=args.page)
            scans = scans_response.get('all_scans', [])
            
            if not scans:
                print(f"No scans found for organization ID '{args.org_id}'.")
                return
            
            print(f"\nScans List for Organization ID: {args.org_id}")
            print(f"{'Scan ID':<20} {'Group ID':<40} {'Project ID':<40} {'Status':<15} {'Created At':<25}")
            print("="*140)
            
            for scan in scans:
                scan_id = scan.get('id', 'N/A')
                group_id = scan.get('group', 'N/A')
                project_id = scan.get('project', 'N/A')
                status = scan.get('status', 'N/A')
                created_at = scan.get('created_at', 'N/A')
                
                print(f"{scan_id:<20} {group_id:<40} {project_id:<40} {status:<15} {created_at:<25}")
            print("\n\n")

    except ValueError as ve:
        print(ve)

    except Exception as e:
        logger.error(f"Error occurred: {str(e)}")

if __name__ == "__main__":
    main()
