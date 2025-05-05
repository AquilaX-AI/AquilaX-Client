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
import re
import tempfile
import zipfile

colorama.init(autoreset=True)
CONFIG_PATH = os.path.expanduser("~/.aquilax/config.json")

ALL_SCANNERS = [
    'pii_scanner', 'secret_scanner', 'iac_scanner', 'sast_scanner',
    'sca_scanner', 'container_scanner', 'image_scanner', 'cicd_scanner'
]


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

def format_bold_texts(text):
    pattern = r'\*\*(.*?)\*\*'
    colors = [Fore.GREEN]
    counter = 0

    def replacer(match):
        nonlocal counter
        inner_text = match.group(1)
        color = colors[counter % len(colors)]
        counter += 1
        return f"{color}{Style.BRIGHT}**{inner_text}**{Style.RESET_ALL}"

    return re.sub(pattern, replacer, text)

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
            tablefmt="rounded_grid"
        )
        print(f"\nFindings:\n{table}")


def save_config(config):
    os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
    with open(CONFIG_PATH, 'w') as f:
        json.dump(config, f, indent=4)

def get_version():
    try:
        version = "1.2.8"
        return version
    except Exception as e:
        logger.error(f"Failed to get the version")
        return "Unknown"

def format_bold_text(text):
    pattern = r'\*\*(.*?)\*\*'
    
    def replacer(match):
        inner_text = match.group(1)
        return f"{Fore.BLUE}{Style.BRIGHT}**{inner_text}**{Style.RESET_ALL}"
    
    formatted_text = re.sub(pattern, replacer, text)
    return formatted_text

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

    # CICD SCAN
    ci_parser = subparsers.add_parser('ci-scan', help='Run a CI/CD scan')
    ci_parser.add_argument('git', help='Git repository URI')
    ci_parser.add_argument('--org-id', help='Organization ID')
    ci_parser.add_argument('--group-id', help='Group ID')
    ci_parser.add_argument('--fail-on-vulns', action='store_true', help='Fail the pipeline if vulnerabilities are found')
    ci_parser.add_argument('--branch', default='main', help='Git branch to scan (default: main)')
    ci_parser.add_argument('--sync', action='store_true', help='Enable sync mode to fetch scan results periodically') 
    ci_parser.add_argument('--output-dir', default='.', help='Directory to save the PDF report')
    ci_parser.add_argument('--save-pdf', action='store_true', help='Save the PDF report locally')

    # Pull command
    pull_parser = subparsers.add_parser('pull', help='Fetch scan by scan_id')
    pull_parser.add_argument('scan_id', help='Scan ID to pull')
    pull_parser.add_argument('--org-id', help='Organization ID (optional, if not provided, the default org ID will be used)')
    pull_parser.add_argument('--format', choices=['json', 'table', 'sarif'], default='table', help='Output format: json, sarif, or table')

    # File-scan command
    file_scan_parser = subparsers.add_parser('file-scan', help='Upload and scan a zip file or a directory')
    file_scan_parser.add_argument('file', help='Path to the zip file or directory to scan')
    file_scan_parser.add_argument('--org-id', help='Organization ID (if not provided, default from config is used)')
    file_scan_parser.add_argument('--group-id', help='Group ID (if not provided, default from config is used)')
    file_scan_parser.add_argument('--scanners', nargs='+', default=['pii_scanner', 'secret_scanner'], 
                                  help='Scanners to use (e.g., pii_scanner secret_scanner)')
    file_scan_parser.add_argument('--tags', nargs='+', default=['aquilax', 'file-scan'], 
                                  help='Tags for the scan')


    # Scan command
    scan_parser = subparsers.add_parser('scan', help='Start a scan with Git URI')
    scan_parser.add_argument('git', help='Git repository URI')
    scan_parser.add_argument('--scanners', nargs='+', default=['pii_scanner', 'secret_scanner', "iac_scanner", "sast_scanner", "sca_scanner", "container_scanner", "image_scanner", "cicd_scanner"], help='Scanners to use')
    scan_parser.add_argument('--public', type=bool, default=True, help='Set scan visibility to public')
    scan_parser.add_argument('--frequency', default='Once', help='Scan frequency')
    scan_parser.add_argument('--tags', nargs='+', default=['aquilax', 'cli', 'tool'], help='Tags for the scan')
    scan_parser.add_argument('--format', choices=['json', 'table'], default='table', help='Output format: json or table')
    scan_parser.add_argument('--sync', action='store_true', help="Enable sync mode to fetch scan results periodically")
    scan_parser.add_argument('--branch', default='main', help='Git branch to scan (default: main)')
    ci_parser.add_argument('--format', choices=['json', 'table'], default='table', help='Output format: json or table')

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
            scan_details = client.get_scan_by_id(org_id, args.scan_id)

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
                                finding.get('vuln', 'N/A')[:47] + "..." if len(finding.get('vuln', 'N/A')) > 50 else finding.get('vuln', 'N/A'),
                                finding.get('severity', 'N/A')
                            ])
                    findings_table = tabulate(
                        all_findings,
                        headers=["Scanner", "Path", "Vulnerability", "Severity"],
                        tablefmt="rounded_grid"
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

        if args.command == 'scan':
            org_id = config.get('org_id')
            group_id = config.get('group_id')

            if not org_id:
                print("Organization ID is not set. Please set it using --set-org <org_id>.")
                return

            if not group_id:
                print("Group ID is not set. Please set it using --set-group <group_id>.")
                return

            # Start Scan
            scan_response = client.start_scan(   org_id, group_id, args.git, args.branch  )
            scan_id = scan_response.get('scan_id')

            if scan_id:
                scan_data = {
                    "Scan ID": scan_id,
                    "Git URI": args.git
                }

                if args.format == 'json':
                    print(json.dumps(scan_data, indent=4))
                else:
                    table = tabulate(scan_data.items(), headers=["Detail", "Value"], tablefmt="grid")
                    print(f"\nScanning Started:\n{table}")

                if args.sync:
                    print("\nSync mode enabled...\n")
                    current_findings = set()
                    loading_index = 0

                    while True:
                        time.sleep(0.3)

                        try:
                            scan_details = client.get_scan_by_id(org_id, group_id, scan_id)
                        except requests.HTTPError as http_err:
                            logger.error(f"HTTP error occurred: {http_err}")
                            print(f"\nResponse: {http_err.response.text}")
                            break
                        except Exception as e:
                            logger.error(f"Error occurred: {str(e)}")
                            break

                        status = scan_details.get('status', 'N/A')

                        results = scan_details.get('results', [])
                        new_findings = []

                        for result in results:
                            scanner_name = result.get('scanner', 'N/A')
                            findings_list = result.get('findings', [])

                            for finding in findings_list:
                                finding_entry = (
                                    scanner_name,
                                    finding.get('path', 'N/A'),
                                    finding.get('vuln', 'N/A')[:47] + "..." if len(finding.get('vuln', 'N/A')) > 50 else finding.get('vuln', 'N/A'),
                                    finding.get('severity', 'N/A').upper()
                                )
                                if finding_entry not in current_findings:
                                    current_findings.add(finding_entry)
                                    new_findings.append(finding_entry)

                        if args.format == 'json':
                            print(json.dumps(list(current_findings), indent=4))
                        else:
                            print_status_and_findings(status, list(current_findings), loading_index)

                        loading_index += 1

                        if status in ['COMPLETED', 'FAILED']:
                            security_policy = scan_details.get('security_policy', {})
                            if not security_policy:
                                print(f"{Fore.YELLOW}Warning: security_policy not found in scan details. Using default thresholds.{Style.RESET_ALL}")
                            thresholds = security_policy.get('threshold', {})
                            total_threshold = thresholds.get('total', sys.maxsize)
                            high_threshold = thresholds.get('HIGH', sys.maxsize)
                            medium_threshold = thresholds.get('MEDIUM', sys.maxsize)
                            low_threshold = thresholds.get('LOW', sys.maxsize)

                            severity_counts = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'CRITICAL': 0, 'UNKNOWN': 0}
                            for _, _, _, severity in current_findings:
                                if severity in severity_counts:
                                    severity_counts[severity] += 1
                                else:
                                    severity_counts['UNKNOWN'] += 1

                            total_findings = sum(severity_counts.values())

                            fail = False
                            fail_reasons = []

                            if total_findings >= total_threshold:
                                fail = True
                                fail_reasons.append(f"Total findings ({total_findings}) >= threshold ({total_threshold})")

                            for severity in ['HIGH', 'MEDIUM', 'LOW', 'CRITICAL', 'UNKNOWN']:
                                count = severity_counts.get(severity, 0)
                                threshold = thresholds.get(severity, sys.maxsize)
                                if count >= threshold:
                                    fail = True
                                    fail_reasons.append(f"{severity} findings ({count}) >= threshold ({threshold})")

                            if fail:
                                print(f"\nScan Status: {status}")
                                print(f"{Fore.RED}Thresholds exceeded: {'; '.join(fail_reasons)}{Style.RESET_ALL}")
                                sys.exit(1)
                            else:
                                if current_findings:
                                    print(f"\nScan Status: {status}")
                                    print(f"{Fore.YELLOW}Number of vulnerabilities found: {len(current_findings)}{Style.RESET_ALL}")
                                else:
                                    print(f"\nScan Status: {status}")
                                    print(f"{Fore.GREEN}No Vulnerabilities Found{Style.RESET_ALL}")

                            break

            else:
                print("Unable to start the scan.")
                sys.exit(0)


        elif args.command == 'file-scan':
            org_id = args.org_id or config.get('org_id')
            group_id = args.group_id or config.get('group_id')
            if not org_id:
                print("Organization ID is required. Please provide it with --org-id or set a default using --set-org.")
                return
            if not group_id:
                print("Group ID is required. Please provide it with --group-id or set a default using --set-group.")
                return

            zip_file_path = args.file
            if os.path.isdir(args.file):
                if args.file in [".", "./"]:
                    folder_path = os.getcwd()
                    folder_name = os.path.basename(folder_path)
                else:
                    folder_name = os.path.basename(os.path.normpath(args.file))
                    
                zip_file_path = os.path.join(tempfile.gettempdir(), f"{folder_name}.zip")
                print(f"Directory: {args.file}. Creating a ZIP archive named {folder_name}.zip for scanning.")
                with zipfile.ZipFile(zip_file_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                    for root, dirs, files in os.walk(args.file):
                        for file in files:
                            file_path = os.path.join(root, file)
                            arcname = os.path.relpath(file_path, args.file)
                            zipf.write(file_path, arcname)
                print(f"Created ZIP archive at {zip_file_path} - Starting Scan...")

            scanners = args.scanners
            if scanners == ['all']:
                scanners = ALL_SCANNERS

            client = APIClient()
            try:
                response = client.start_file_scan(
                    org_id,
                    group_id,
                    zip_file_path,
                    {scanner: True for scanner in scanners},
                    args.tags
                )
                file_scan_id = response.get('scan_id')
                if file_scan_id:
                    print(f"File scan started successfully with Scan ID: {file_scan_id}")
                else:
                    print("File-scan request completed, but no Scan ID was returned.")
            except Exception as e:
                print(f"Error starting file scan: {str(e)}")
            finally:
                if os.path.isdir(args.file) and os.path.exists(zip_file_path):
                    os.remove(zip_file_path)


        elif args.command == 'ci-scan':
            org_id = args.org_id or config.get('org_id')
            group_id = args.group_id or config.get('group_id')

            if not org_id:
                print("Organization ID is not set. Please provide it using --org-id or set a default using --set-org.")
                sys.exit(0)

            if not group_id:
                print("Group ID is not set. Please provide it using --group-id or set a default using --set-group.")
                sys.exit(0)

            # Debugging
            print(f"Branch: {args.branch}")

            try:
                scan_response = client.start_scan(
                    org_id,
                    group_id,
                    args.git,
                    args.branch
                )
            except requests.RequestException as req_err:
                logger.error(f"API request failed: {str(req_err)}")
                print(f"{Fore.RED}API request failed: {str(req_err)}{Style.RESET_ALL}")
                sys.exit(0)
            except Exception as e:
                logger.error(f"Unexpected error during scan initiation: {str(e)}")
                print(f"{Fore.RED}Unexpected error: {str(e)}{Style.RESET_ALL}")
                sys.exit(0) 

            scan_id = scan_response.get('scan_id')

            if scan_id:
                print(f"Scan started with ID: {scan_id}.")

                if args.sync:
                    # Sync Mode:
                    print("Sync mode enabled.\n")
                    current_findings = set()
                    loading_index = 0

                    while True:
                        time.sleep(1)

                        try:
                            scan_details = client.get_scan_by_id(org_id, group_id, scan_id)
                        except requests.HTTPError as http_err:
                            logger.error(f"HTTP error occurred: {http_err}")
                            print(f"\nResponse: {http_err.response.text}")
                            sys.exit(0)
                        except Exception as e:
                            logger.error(f"Error occurred: {str(e)}")
                            sys.exit(0)

                        status = scan_details.get('status', 'N/A')
                        results = scan_details.get('results', [])
                        new_findings = []

                        for result in results:
                            scanner_name = result.get('scanner', 'N/A')
                            findings_list = result.get('findings', [])

                            for finding in findings_list:
                                finding_entry = (
                                    scanner_name,
                                    finding.get('path', 'N/A'),
                                    finding.get('vuln', 'N/A')[:47] + "..." if len(finding.get('vuln', 'N/A')) > 50 else finding.get('vuln', 'N/A'),
                                    finding.get('severity', 'N/A').upper()
                                )
                                if finding_entry not in current_findings:
                                    current_findings.add(finding_entry)
                                    new_findings.append(finding_entry)

                        if args.format == 'json':
                            print(json.dumps(list(current_findings), indent=4))
                        else:
                            print_status_and_findings(status, list(current_findings), loading_index)

                        loading_index += 1

                        if status in ['COMPLETED', 'FAILED']:
                            security_policy = scan_details.get('security_policy', {})
                            if not security_policy:
                                print(f"{Fore.YELLOW}Warning: security_policy not found in scan details. Using default thresholds.{Style.RESET_ALL}")
                            thresholds = security_policy.get('threshold', {})
                            total_threshold = thresholds.get('total', sys.maxsize)
                            high_threshold = thresholds.get('HIGH', sys.maxsize)
                            medium_threshold = thresholds.get('MEDIUM', sys.maxsize)
                            low_threshold = thresholds.get('LOW', sys.maxsize)

                            print("\n**Security Policy Thresholds:**")
                            print(f"  - Total: {total_threshold}")
                            print(f"  - HIGH: {high_threshold}")
                            print(f"  - MEDIUM: {medium_threshold}")
                            print(f"  - LOW: {low_threshold}\n")

                            severity_counts = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'CRITICAL': 0, 'UNKNOWN': 0}
                            for _, _, _, severity in current_findings:
                                if severity in severity_counts:
                                    severity_counts[severity] += 1
                                else:
                                    severity_counts['UNKNOWN'] += 1

                            total_findings = sum(severity_counts.values())

                            fail = False
                            fail_reasons = []

                            if total_findings >= total_threshold:
                                fail = True
                                fail_reasons.append(f"Total findings ({total_findings}) >= threshold ({total_threshold})")

                            for severity in ['HIGH', 'MEDIUM', 'LOW', 'CRITICAL', 'UNKNOWN']:
                                count = severity_counts.get(severity, 0)
                                threshold = thresholds.get(severity, sys.maxsize)
                                if count >= threshold:
                                    fail = True
                                    fail_reasons.append(f"{severity} findings ({count}) >= threshold ({threshold})")

                            if fail:
                                print(f"{Fore.RED}Thresholds exceeded: {'; '.join(fail_reasons)}{Style.RESET_ALL}")
                                sys.exit(1)
                            else:
                                if current_findings:
                                    print(f"{Fore.YELLOW}Number of vulnerabilities found: {len(current_findings)}{Style.RESET_ALL}")
                                else:
                                    print(f"{Fore.GREEN}No Vulnerabilities Found{Style.RESET_ALL}")

                                if args.fail_on_vulns:
                                    print("Vulnerabilities found. Failing the pipeline.")
                                    sys.exit(1)
                            break

                else:
                    # Non-Sync Mode:
                    print("Scanning in progress...", end="", flush=True)
                    previous_status = None
                    while True:
                        time.sleep(1)
                        try:
                            scan_details = client.get_scan_by_id(org_id, group_id, scan_id)
                        except requests.RequestException as req_err:
                            print(f"\r{Fore.RED}API request failed: {str(req_err)}{Style.RESET_ALL}")
                            logger.error(f"API request failed while fetching scan details: {str(req_err)}")
                            sys.exit(0)
                        except Exception as e:
                            print(f"\r{Fore.RED}Unexpected error: {str(e)}{Style.RESET_ALL}")
                            logger.error(f"Unexpected error while fetching scan details: {str(e)}")
                            sys.exit(0)

                        status = scan_details.get('status', 'N/A')
                        if previous_status != status:
                            print(f"\rScan status: {status}. Waiting...", end="", flush=True)
                            previous_status = status
                        else:
                            print(".", end="", flush=True)
                            
                        if status == 'COMPLETED':
                            print("\nScan completed successfully.")
                            break
                        elif status == 'FAILED':
                            print("\nScan failed.")
                            sys.exit(1)

                    security_policy = scan_details.get('security_policy', {})
                    if not security_policy:
                        print(f"{Fore.YELLOW}Warning: security_policy not found in scan details. Using default thresholds.{Style.RESET_ALL}")
                    thresholds = security_policy.get('threshold', {})
                    total_threshold = thresholds.get('total', sys.maxsize)
                    high_threshold = thresholds.get('HIGH', sys.maxsize)
                    medium_threshold = thresholds.get('MEDIUM', sys.maxsize)
                    low_threshold = thresholds.get('LOW', sys.maxsize)

                    print("\n**Security Policy Thresholds:**")
                    print(f"  - Total: {total_threshold}")
                    print(f"  - HIGH: {high_threshold}")
                    print(f"  - MEDIUM: {medium_threshold}")
                    print(f"  - LOW: {low_threshold}\n")

                    severity_counts = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'CRITICAL': 0, 'UNKNOWN': 0}
                    results = scan_details.get('results', [])
                    all_findings = []
                    
                    for result in results:
                        scanner_name = result.get('scanner', 'N/A')
                        findings = result.get('findings', [])
                        for finding in findings:
                            severity = finding.get('severity', 'UNKNOWN').upper()
                            if severity in severity_counts:
                                severity_counts[severity] += 1
                            else:
                                severity_counts['UNKNOWN'] += 1
                                
                            all_findings.append([
                                scanner_name,
                                finding.get('path', 'N/A'),
                                finding.get('vuln', 'N/A')[:47] + "..." if len(finding.get('vuln', 'N/A')) > 50 else finding.get('vuln', 'N/A'),
                                color_severity(severity)
                            ])

                    total_findings = sum(severity_counts.values())
                    
                    if all_findings:
                        print("\nFindings Summary:")
                        findings_table = tabulate(
                            all_findings,
                            headers=["Scanner", "Path", "Vulnerability", "Severity"],
                            tablefmt="rounded_grid"
                        )
                        print(findings_table)
                    else:
                        print(f"{Fore.GREEN}No vulnerabilities found.{Style.RESET_ALL}")

                    fail = False
                    fail_reasons = []

                    if total_findings >= total_threshold:
                        fail = True
                        fail_reasons.append(f"Total findings ({total_findings}) >= threshold ({total_threshold})")

                    for severity in ['HIGH', 'MEDIUM', 'LOW', 'CRITICAL', 'UNKNOWN']:
                        count = severity_counts.get(severity, 0)
                        threshold = thresholds.get(severity, sys.maxsize)
                        if count >= threshold:
                            fail = True
                            fail_reasons.append(f"{severity} findings ({count}) >= threshold ({threshold})")

                    if fail:
                        print(f"\n{Fore.RED}Thresholds exceeded: {'; '.join(fail_reasons)}{Style.RESET_ALL}")
                        sys.exit(1)
                    else:
                        print(f"\nNumber of vulnerabilities found: {total_findings}")
                        if args.fail_on_vulns and total_findings > 0:
                            print("Vulnerabilities found. Failing the pipeline.")
                            sys.exit(1)

                    try:
                        sarif_results = client.get_scan_results_sarif(org_id, scan_id)
                        with open('results.sarif', 'w') as sarif_file:
                            json.dump(sarif_results, sarif_file, indent=4)
                        print("SARIF results saved to 'results.sarif'.")
                    except Exception as e:
                        logger.error(f"Failed to fetch or save SARIF results: {str(e)}")
                        print("Failed to fetch or save SARIF results.")

                try:
                    dashboard_link = f"https://aquilax.ai/app/scan/{org_id}/{scan_id}/{group_id}"
                    print("\n--------------")
                    print(f"View the full scan results on the dashboard: {Fore.BLUE}{dashboard_link}{Style.RESET_ALL}")
                    print("\n")

                except Exception as e:
                    logger.error(f"Failed to construct dashboard link: {str(e)}")
                    print(f"{Fore.RED}Failed to construct dashboard link: {str(e)}{Style.RESET_ALL}")

            else:
                print(f"{Fore.RED}Unable to start the scan.{Style.RESET_ALL}")
                sys.exit(0)


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
                                finding.get('vuln', 'N/A')[:47] + "..." if len(finding.get('vuln', 'N/A')) > 50 else finding.get('vuln', 'N/A'),
                                finding.get('severity', 'N/A')
                            ])

                    if not all_findings:
                        print("No findings across all scanners.")
                        return

                    table = tabulate(
                        all_findings,
                        headers=["Scanner", "Path", "Vulnerability", "Severity"],
                        tablefmt="rounded_grid"
                    )
                    print(table)

    except ValueError as ve:
        print(ve)

    except Exception as e:
        logger.error(f"Error occurred: {str(e)}")

if __name__ == "__main__":
    main()