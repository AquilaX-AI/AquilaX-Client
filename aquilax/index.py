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
import shutil

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
    
def _term_width():
    """Return the current terminal/runner column width (min 80, default 120)."""
    try:
        return max(80, shutil.get_terminal_size(fallback=(120, 24)).columns)
    except Exception:
        return 120


def print_findings_table(rows, headers, title=None):
    """Print a findings table that adapts to the available terminal width.

    On wide terminals (>=120 cols) a bordered rounded_grid is used.
    On narrow terminals a plain `simple` format is used and each column is
    capped so the total row width stays within the available space.
    """
    width = _term_width()
    if title:
        print(title)

    if not rows:
        return

    if width >= 120:
        # Comfortable width — use full bordered style with generous col caps
        col_caps = {
            "Scanner":       18,
            "Path":          30,
            "Vulnerability": 45,
            "Severity":       8,
            "CWE":           20,
            "OWASP":         20,
        }
        fmt = "rounded_grid"
    else:
        # Narrow runner / terminal — drop borders, tighten every column
        # Reserve ~3 chars per separator and ~2 for the severity col itself
        n_cols = len(headers)
        overhead = n_cols * 3          # spaces between columns
        budget   = width - overhead
        # Fixed widths: Severity=8, Scanner=12; split the rest between Path & Vuln
        fixed    = 8 + 12             # Severity + Scanner
        flexible = max(10, budget - fixed)
        path_w   = max(10, flexible // 3)
        vuln_w   = max(15, flexible - path_w)
        col_caps = {
            "Scanner":       12,
            "Path":          path_w,
            "Vulnerability": vuln_w,
            "Severity":       8,
            "CWE":           15,
            "OWASP":         15,
        }
        fmt = "simple"

    # Build per-column maxcolwidths list in header order
    max_widths = [col_caps.get(h, 20) for h in headers]

    table = tabulate(
        rows,
        headers=headers,
        tablefmt=fmt,
        maxcolwidths=max_widths,
    )
    print(table)


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
        print()
        print_findings_table(
            colored_findings,
            headers=["Scanner", "Path", "Vulnerability", "Severity"],
            title="Findings:",
        )


def save_config(config):
    os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
    with open(CONFIG_PATH, 'w') as f:
        json.dump(config, f, indent=4)

def get_version():
    try:
        current_dir = os.path.dirname(os.path.abspath(__file__))
        version_file = os.path.join(current_dir, '..', 'VERSION')
        
        if not os.path.exists(version_file):
            version_file = os.path.join(current_dir, 'VERSION')
        
        if os.path.exists(version_file):
            with open(version_file, 'r') as f:
                return f.read().strip()
        else:
            try:
                from importlib.metadata import version
                return version('aquilax')
            except:
                return "Unknown"
    except Exception as e:
        logger.error(f"Failed to get the version: {e}")
        return "Unknown"

def format_bold_text(text):
    pattern = r'\*\*(.*?)\*\*'
    
    def replacer(match):
        inner_text = match.group(1)
        return f"{Fore.BLUE}{Style.BRIGHT}**{inner_text}**{Style.RESET_ALL}"
    
    formatted_text = re.sub(pattern, replacer, text)
    return formatted_text

def convert_to_sarif(scan_details, scan_id):
    """Convert scan results to SARIF 2.1.0 format."""
    sarif_results = []
    sarif_rules = []
    rule_ids_seen = set()
    
    # Extract findings from scan details
    if 'findings' in scan_details:
        findings_list = scan_details['findings']
    else:
        results = scan_details.get('results', [])
        findings_list = []
        for result in results:
            findings_list.extend(result.get('findings', []))
    
    # Convert each finding to SARIF format
    for finding in findings_list:
        vuln_name = finding.get('vuln', 'Unknown Vulnerability')
        scanner = finding.get('scanner', 'unknown')
        severity = finding.get('severity', 'UNKNOWN').upper()
        path = finding.get('path', '')
        line_start = finding.get('line_start', 1)
        line_end = finding.get('line_end', line_start)
        description = finding.get('description', '')
        cwe_list = finding.get('cwe', [])
        owasp_list = finding.get('owasp', [])
        
        # Map severity to SARIF level
        level_map = {
            'CRITICAL': 'error',
            'HIGH': 'error',
            'MEDIUM': 'warning',
            'LOW': 'note',
            'UNKNOWN': 'none'
        }
        level = level_map.get(severity, 'warning')
        
        # Create rule ID
        rule_id = f"{scanner}_{vuln_name.replace(' ', '_').replace('/', '_')}"[:100]
        
        # Add rule if not seen before
        if rule_id not in rule_ids_seen:
            rule_ids_seen.add(rule_id)
            rule = {
                "id": rule_id,
                "name": vuln_name,
                "shortDescription": {"text": vuln_name},
                "fullDescription": {"text": description or vuln_name},
                "help": {
                    "text": f"Scanner: {scanner}\nCWE: {', '.join(cwe_list) if cwe_list else 'N/A'}\nOWASP: {', '.join(owasp_list) if owasp_list else 'N/A'}"
                },
                "defaultConfiguration": {"level": level},
                "properties": {
                    "security-severity": str({'CRITICAL': '9.5', 'HIGH': '7.5', 'MEDIUM': '5.5', 'LOW': '3.5', 'UNKNOWN': '0'}.get(severity, '0')),
                    "tags": [scanner, severity.lower()] + cwe_list + owasp_list
                }
            }
            sarif_rules.append(rule)
        
        # Create SARIF result
        sarif_result = {
            "ruleId": rule_id,
            "level": level,
            "message": {"text": description or vuln_name},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": path},
                    "region": {
                        "startLine": line_start,
                        "endLine": line_end
                    }
                }
            }]
        }
        sarif_results.append(sarif_result)
    
    # Build complete SARIF document
    sarif_document = {
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Aquilax",
                    "version": "1.0.0",
                    "informationUri": "https://aquilax.ai",
                    "rules": sarif_rules
                }
            },
            "results": sarif_results,
            "properties": {
                "scanId": scan_id
            }
        }]
    }
    
    return sarif_document


def parse_and_display_findings(scan_details, org_id, group_id):
    """Common function to parse findings and display table post-scan."""
    all_findings = []
    severity_counts = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'CRITICAL': 0, 'UNKNOWN': 0}

    # Check for new format: findings directly in scan_details
    if 'findings' in scan_details:
        findings_list = scan_details['findings']
        for finding in findings_list:
            scanner_name = finding.get('scanner', 'N/A')
            severity = finding.get('severity', 'UNKNOWN').upper()
            if severity in severity_counts:
                severity_counts[severity] += 1
            vuln_name = finding.get('vuln', 'N/A')[:47] + "..." if len(finding.get('vuln', 'N/A')) > 50 else finding.get('vuln', 'N/A')
            cwe = ', '.join(finding.get('cwe', [])) if isinstance(finding.get('cwe'), list) else str(finding.get('cwe', 'N/A'))
            owasp = ', '.join(finding.get('owasp', [])) if isinstance(finding.get('owasp'), list) else str(finding.get('owasp', 'N/A'))
            all_findings.append([
                scanner_name,
                finding.get('path', 'N/A'),
                vuln_name,
                color_severity(severity),
                cwe,
                owasp
            ])
    else:
        # Old format: results with findings
        results = scan_details.get('results', [])
        for result in results:
            scanner_name = result.get('scanner', 'N/A')
            findings = result.get('findings', [])
            for finding in findings:
                severity = finding.get('severity', 'UNKNOWN').upper()
                if severity in severity_counts:
                    severity_counts[severity] += 1
                vuln_name = finding.get('vuln', 'N/A')[:47] + "..." if len(finding.get('vuln', 'N/A')) > 50 else finding.get('vuln', 'N/A')
                cwe = finding.get('cwe', 'N/A')
                owasp = finding.get('owasp', 'N/A')
                all_findings.append([
                    scanner_name,
                    finding.get('path', 'N/A'),
                    vuln_name,
                    color_severity(severity),
                    cwe,
                    owasp
                ])

    total_findings = sum(severity_counts.values())
    return all_findings, severity_counts, total_findings

def print_thresholds_and_fail_check(severity_counts, total_findings, client, org_id, group_id, fail_on_vulns=False, status='COMPLETED'):
    """Print thresholds and perform fail check."""
    # Default thresholds
    default_thresholds = {'total': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'CRITICAL': 0, 'UNKNOWN': 0}
    thresholds = default_thresholds.copy()
    try:
        policy = client.get_group_policy(org_id, group_id)
        thresholds.update(policy)
    except Exception as e:
        logger.warning(f"Failed to fetch group policy thresholds: {e}. Using defaults.")

    print("\n**Security Policy Thresholds:**")
    for sev, thresh in thresholds.items():
        print(f"  - {sev}: {thresh}")

    fail = False
    fail_reasons = []
    if total_findings > thresholds['total']:
        fail = True
        fail_reasons.append(f"Total ({total_findings}) > {thresholds['total']}")
    for severity in severity_counts:
        if severity == 'UNKNOWN':
            continue
        count = severity_counts[severity]
        if count > thresholds.get(severity, 0):
            fail = True
            fail_reasons.append(f"{severity} ({count}) > {thresholds[severity]}")

    if fail:
        print(f"{Fore.RED}Thresholds exceeded: {'; '.join(fail_reasons)}{Style.RESET_ALL}")
        sys.exit(1)
    else:
        print(f"\nScan Status: {status}")
        if total_findings > 0:
            print(f"{Fore.YELLOW}Number of vulnerabilities found: {total_findings} (Breakdown: {severity_counts}){Style.RESET_ALL}")
        else:
            print(f"{Fore.GREEN}No Vulnerabilities Found{Style.RESET_ALL}")

    if fail_on_vulns and total_findings > 0:
        print("Vulnerabilities found. Failing the pipeline.")
        sys.exit(1)

def _print_welcome(version):
    W  = Style.BRIGHT + Fore.WHITE
    C  = Style.BRIGHT + Fore.CYAN
    DIM = Style.DIM   + Fore.WHITE
    R  = Style.RESET_ALL

    banner = f"""
{C}
  █████╗  ██████╗ ██╗   ██╗██╗██╗      █████╗ ██╗  ██╗
 ██╔══██╗██╔═══██╗██║   ██║██║██║     ██╔══██╗╚██╗██╔╝
 ███████║██║   ██║██║   ██║██║██║     ███████║ ╚███╔╝
 ██╔══██║██║▄▄ ██║██║   ██║██║██║     ██╔══██║ ██╔██╗
 ██║  ██║╚██████╔╝╚██████╔╝██║███████╗██║  ██║██╔╝ ██╗
 ╚═╝  ╚═╝ ╚══▀▀═╝  ╚═════╝ ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝
{R}"""

    print(banner)
    print(f"  {W}AI-Powered Application Security Platform{R}  {DIM}v{version}{R}")
    print(f"  {DIM}https://aquilax.ai{R}")
    print()

    w = _term_width()
    print(Fore.CYAN + Style.BRIGHT + "─" * min(w, 70) + R)
    print()

    commands = [
        ("login <token>",      "Authenticate with your AquilaX API token"),
        ("logout",             "Remove saved credentials"),
        ("analyze <path>",     "Scan a local file or directory for vulnerabilities"),
        ("scan <git-uri>",     "Start a remote repository scan"),
        ("ci-scan <git-uri>",  "Run a scan in CI/CD mode with threshold enforcement"),
        ("pull <scan-id>",     "Fetch and display results of a previous scan"),
        ("get orgs",           "List all organizations you have access to"),
        ("get groups",         "List all groups within an organization"),
        ("get scan-details",   "Show full details of a specific scan"),
    ]

    options = [
        ("--set-org <id>",     "Save a default organization ID"),
        ("--set-group <id>",   "Save a default group ID"),
        ("-v, --version",      "Show the installed version"),
    ]

    cmd_col  = 26
    desc_col = 44

    print(f"  {W}COMMANDS{R}")
    print()
    for cmd, desc in commands:
        cmd_str  = f"{Fore.CYAN}{Style.BRIGHT}aquilax {cmd}{R}"
        pad      = max(1, cmd_col - len(cmd))
        print(f"    {cmd_str}{' ' * pad}{DIM}{desc}{R}")
    print()

    print(f"  {W}OPTIONS{R}")
    print()
    for opt, desc in options:
        opt_str = f"{Fore.YELLOW}{opt}{R}"
        pad     = max(1, cmd_col - len(opt) + 8)
        print(f"    {opt_str}{' ' * pad}{DIM}{desc}{R}")
    print()

    print(Fore.CYAN + Style.BRIGHT + "─" * min(w, 70) + R)
    print()
    print(f"  {DIM}Run {R}{Fore.CYAN}aquilax <command> --help{R}{DIM} for detailed usage of any command.{R}")
    print()


def main():
    parser = argparse.ArgumentParser(description="Aquilax API Client", add_help=False)

    config = load_config()

    # Get the version from the VERSION file
    version = get_version()
    parser.add_argument('-h', '--help', action='store_true', help='Show this help message and exit')
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
    ci_parser.add_argument('--format', choices=['json', 'table'], default='table', help='Output format: json or table')

    # Pull command
    pull_parser = subparsers.add_parser('pull', help='Fetch scan by scan_id')
    pull_parser.add_argument('scan_id', help='Scan ID to pull')
    pull_parser.add_argument('--org-id', help='Organization ID (optional, if not provided, the default org ID will be used)')
    pull_parser.add_argument('--group-id', help='Group ID (optional, if not provided, the default group ID will be used)')
    pull_parser.add_argument('--format', choices=['json', 'table'], default='table', help='Output format: json or table')

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

    get_parser = subparsers.add_parser('get', help='Get information')
    get_subparsers = get_parser.add_subparsers(dest='get_command')

    get_orgs_parser = get_subparsers.add_parser('orgs', help='Get all organizations')

    get_scan_details_parser = get_subparsers.add_parser('scan-details', help='Get scan details')
    get_scan_details_parser.add_argument('--org-id', help='Organization ID')
    get_scan_details_parser.add_argument('--group-id', help='Group ID')
    get_scan_details_parser.add_argument('--scan-id', required=True, help='Scan ID')
    get_scan_details_parser.add_argument('--format', choices=['json', 'table'], default='table', help='Output format: json or table')

    # Get All Organizations command
    get_groups_parser = get_subparsers.add_parser('groups', help='Get all groups for an organization')
    get_groups_parser.add_argument('--org-id', default=config.get('org_id'), help='Organization ID')

    # Add the login command
    login_parser = subparsers.add_parser('login', help='Login to Aquilax by setting the API token')
    login_parser.add_argument('token', help='API Token for authentication')
    
    default_server = os.getenv("AQUILAX_SERVER", "https://aquilax.ai")

    login_parser.add_argument('--server', default=default_server, help='AquilaX Server in use (default: https://aquilax.ai)')

    logout_parser = subparsers.add_parser('logout', help='Logout and remove the API token')

    # Analyze command
    analyze_parser = subparsers.add_parser('analyze', help='Scan a local file or directory for vulnerabilities')
    analyze_parser.add_argument('target', help='File path or directory to analyze (e.g., app.py or .)')
    analyze_parser.add_argument('--org-id', help='Organization ID')
    analyze_parser.add_argument('--group-id', help='Group ID')

    args = parser.parse_args()

    if args.command == 'login':
        config['apiToken'] = args.token
        config['baseUrl'] = args.server

        save_config(config)
        print(f"Auth Configuration Saved successfully! \n")
        return

    if args.command == 'logout':
        config.pop('apiToken', None)
        config.pop('baseUrl', None)
        save_config(config)
        print("Auth Configuration Removed successfully!. \n")
        return
    
    if args.command == 'pull':
        client = APIClient()

        org_id = args.org_id or config.get('org_id')
        group_id = args.group_id or config.get('group_id')

        if not org_id:
            print(f"Organization ID is required but not provided and no default is set.")
            return
        if not group_id:
            print(f"Group ID is required but not provided and no default is set.")
            return

        try:
            scan_details = client.get_scan_by_id(org_id, group_id, args.scan_id)

            if not scan_details or "scan" not in scan_details:
                print("No scan details found.")
                return

            output_format = getattr(args, 'format', 'table')

            if output_format == 'json':
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

                all_findings, severity_counts, total_findings = parse_and_display_findings(scan_details, org_id, group_id)
                if all_findings:
                    print_findings_table(
                        all_findings,
                        headers=["Scanner", "Path", "Vulnerability", "Severity", "CWE", "OWASP"],
                        title="\nFindings Summary:",
                    )
                    print(f"{Fore.YELLOW}Total vulnerabilities found: {total_findings} (Breakdown: {severity_counts}){Style.RESET_ALL}")
                else:
                    print(f"{Fore.GREEN}No findings across all scanners.{Style.RESET_ALL}")

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

    if getattr(args, 'help', False) or not args.command:
        _print_welcome(version)
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

                        if 'findings' in scan_details:
                            findings_list = scan_details['findings']
                        else:
                            results = scan_details.get('results', [])
                            findings_list = []
                            for result in results:
                                findings_list.extend(result.get('findings', []))
                        new_findings = []

                        for finding in findings_list:
                            scanner_name = finding.get('scanner', 'N/A')
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
                            # Re-fetch for final fresh data
                            try:
                                scan_details = client.get_scan_by_id(org_id, group_id, scan_id)
                            except Exception as e:
                                logger.error(f"Final fetch failed: {str(e)}")
                                print(f"{Fore.RED}Warning: Could not fetch final details.{Style.RESET_ALL}")
                                return

                            all_findings, severity_counts, total_findings = parse_and_display_findings(scan_details, org_id, group_id)

                            if all_findings:
                                print_findings_table(
                                    all_findings,
                                    headers=["Scanner", "Path", "Vulnerability", "Severity", "CWE", "OWASP"],
                                    title="\nFindings Summary:",
                                )
                                print(f"{Fore.YELLOW}Total vulnerabilities found: {total_findings} (Breakdown: {severity_counts}){Style.RESET_ALL}")
                            else:
                                print(f"{Fore.GREEN}No Vulnerabilities Found{Style.RESET_ALL}")

                            print_thresholds_and_fail_check(severity_counts, total_findings, client, org_id, group_id, status=status)
                            break

            else:
                print("Unable to start the scan.")
                sys.exit(0)

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
                        if 'findings' in scan_details:
                            findings_list = scan_details['findings']
                        else:
                            results = scan_details.get('results', [])
                            findings_list = []
                            for result in results:
                                findings_list.extend(result.get('findings', []))
                        new_findings = []

                        for finding in findings_list:
                            scanner_name = finding.get('scanner', 'N/A')
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
                            # Re-fetch for final fresh data
                            try:
                                scan_details = client.get_scan_by_id(org_id, group_id, scan_id)
                            except Exception as e:
                                logger.error(f"Final fetch failed: {str(e)}")
                                print(f"{Fore.RED}Warning: Could not fetch final details.{Style.RESET_ALL}")
                                return

                            all_findings, severity_counts, total_findings = parse_and_display_findings(scan_details, org_id, group_id)

                            if all_findings:
                                print("\nFindings Summary:")
                                findings_table = tabulate(
                                    all_findings,
                                    headers=["Scanner", "Path", "Vulnerability", "Severity", "CWE", "OWASP"],
                                    tablefmt="rounded_grid"
                                )
                                print(findings_table)
                                print(f"{Fore.YELLOW}Total vulnerabilities found: {total_findings} (Breakdown: {severity_counts}){Style.RESET_ALL}")
                            else:
                                print(f"{Fore.GREEN}No Vulnerabilities Found{Style.RESET_ALL}")

                            print_thresholds_and_fail_check(severity_counts, total_findings, client, org_id, group_id, args.fail_on_vulns, status)
                            
                            # Save SARIF results for CI/CD artifact upload
                            try:
                                print("\nGenerating SARIF report...")
                                sarif_data = convert_to_sarif(scan_details, scan_id)
                                sarif_results_count = len(sarif_data.get('runs', [{}])[0].get('results', []))
                                sarif_file_path = os.path.join(os.getcwd(), 'results.sarif')
                                with open(sarif_file_path, 'w') as sarif_file:
                                    json.dump(sarif_data, sarif_file, indent=2)
                                print(f"{Fore.GREEN}SARIF report saved to: {sarif_file_path} ({sarif_results_count} results){Style.RESET_ALL}")
                            except Exception as e:
                                logger.error(f"Failed to generate SARIF report: {str(e)}")
                                print(f"{Fore.YELLOW}Warning: Failed to generate SARIF report: {str(e)}{Style.RESET_ALL}")
                            
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

                    # Re-fetch for final fresh data
                    try:
                        scan_details = client.get_scan_by_id(org_id, group_id, scan_id)
                    except Exception as e:
                        logger.error(f"Final fetch failed: {str(e)}")
                        print(f"{Fore.RED}Warning: Could not fetch final details.{Style.RESET_ALL}")
                        return

                    all_findings, severity_counts, total_findings = parse_and_display_findings(scan_details, org_id, group_id)

                    if all_findings:
                        print_findings_table(
                            all_findings,
                            headers=["Scanner", "Path", "Vulnerability", "Severity", "CWE", "OWASP"],
                            title="\nFindings Summary:",
                        )
                        print(f"{Fore.YELLOW}Total vulnerabilities found: {total_findings} (Breakdown: {severity_counts}){Style.RESET_ALL}")
                    else:
                        print(f"{Fore.GREEN}No vulnerabilities found.{Style.RESET_ALL}")

                    print_thresholds_and_fail_check(severity_counts, total_findings, client, org_id, group_id, args.fail_on_vulns, status)

                # Save SARIF results for CI/CD artifact upload
                try:
                    print("\nGenerating SARIF report...")
                    sarif_data = convert_to_sarif(scan_details, scan_id)
                    sarif_results_count = len(sarif_data.get('runs', [{}])[0].get('results', []))
                    sarif_file_path = os.path.join(os.getcwd(), 'results.sarif')
                    with open(sarif_file_path, 'w') as sarif_file:
                        json.dump(sarif_data, sarif_file, indent=2)
                    print(f"{Fore.GREEN}SARIF report saved to: {sarif_file_path} ({sarif_results_count} results){Style.RESET_ALL}")
                except Exception as e:
                    logger.error(f"Failed to generate SARIF report: {str(e)}")
                    print(f"{Fore.YELLOW}Warning: Failed to generate SARIF report: {str(e)}{Style.RESET_ALL}")

                try:
                    dashboard_link = f"https://aquilax.ai/app/dashboard/scan-v2/{scan_id}/?org={org_id}&group={group_id}"
                    print("\n--------------")
                    print(f"View the full scan results on the dashboard: {Fore.BLUE}{dashboard_link}{Style.RESET_ALL}")
                    print("\n")

                except Exception as e:
                    logger.error(f"Failed to construct dashboard link: {str(e)}")
                    print(f"{Fore.RED}Failed to construct dashboard link: {str(e)}{Style.RESET_ALL}")

            else:
                print(f"{Fore.RED}Unable to start the scan.{Style.RESET_ALL}")
                sys.exit(0)


        elif args.command == 'analyze':
            org_id = args.org_id or config.get('org_id')
            group_id = args.group_id or config.get('group_id')

            if not org_id:
                print("Organization ID is not set. Please provide it using --org-id or set a default using --set-org.")
                return
            if not group_id:
                print("Group ID is not set. Please provide it using --group-id or set a default using --set-group.")
                return

            target = os.path.abspath(args.target)

            # Collect files to scan
            CODE_EXTENSIONS = {
                '.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.go', '.rb', '.php',
                '.cs', '.cpp', '.c', '.h', '.hpp', '.rs', '.swift', '.kt', '.scala',
                '.sh', '.bash', '.yml', '.yaml', '.tf', '.hcl', '.html', '.css', '.sql', '.xml'
            }
            SKIP_DIRS = {
                '.git', 'node_modules', '__pycache__', '.aquilax', 'venv', '.venv',
                'dist', 'build', '.tox', 'env', 'eggs', '.eggs', 'site-packages',
                '.pytest_cache', '.mypy_cache'
            }
            MAX_FILE_SIZE = 1 * 1024 * 1024  # 1 MB

            files_to_scan = []

            if os.path.isfile(target):
                files_to_scan = [target]
                target_dir = os.path.dirname(target)
            elif os.path.isdir(target):
                target_dir = target
                for root, dirs, files in os.walk(target):
                    dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
                    for fname in files:
                        _, ext = os.path.splitext(fname)
                        if ext.lower() in CODE_EXTENSIONS or fname in ('Dockerfile', 'Makefile'):
                            fpath = os.path.join(root, fname)
                            if os.path.getsize(fpath) <= MAX_FILE_SIZE:
                                files_to_scan.append(fpath)
            else:
                print(f"Target not found: {args.target}")
                return

            if not files_to_scan:
                print("No supported code files found to analyze.")
                return

            print(f"Analyzing: {args.target}")
            print(f"Scanning {len(files_to_scan)} file(s)...\n")

            # Set up output dirs and scan_date early so findings can be timestamped
            aquilax_dir = os.path.join(target_dir, '.aquilax')
            data_dir    = os.path.join(aquilax_dir, 'data')
            os.makedirs(data_dir, exist_ok=True)

            import datetime
            scan_date = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

            # Load existing report for incremental merge
            json_path = os.path.join(data_dir, 'aquilax_ai_findings.json')
            existing_report = {}
            if os.path.exists(json_path):
                try:
                    with open(json_path, 'r', encoding='utf-8') as _ef:
                        existing_report = json.load(_ef)
                except Exception:
                    existing_report = {}

            # Files being scanned now (relative paths) — their old findings will be replaced
            current_rel_paths = {os.path.relpath(f, target_dir) for f in files_to_scan}
            # Keep findings from files NOT in this scan run
            retained_findings = [
                _f for _f in existing_report.get('findings', [])
                if _f.get('file') not in current_rel_paths
            ]

            all_findings = []
            severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'UNKNOWN': 0}

            for fpath in files_to_scan:
                rel_path = os.path.relpath(fpath, target_dir)
                try:
                    with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
                        code = f.read()
                except Exception as e:
                    logger.warning(f"Could not read {fpath}: {e}")
                    continue

                if not code.strip():
                    continue

                try:
                    findings = client.scan_code(org_id, group_id, code)
                except requests.HTTPError as http_err:
                    if http_err.response.status_code == 400:
                        continue  # empty/whitespace code — skip silently
                    logger.error(f"HTTP error scanning {rel_path}: {http_err}")
                    print(f"{Fore.RED}Error scanning {rel_path}: {http_err}{Style.RESET_ALL}")
                    continue
                except Exception as e:
                    logger.error(f"Error scanning {rel_path}: {e}")
                    print(f"{Fore.RED}Error scanning {rel_path}: {e}{Style.RESET_ALL}")
                    continue

                for finding in findings:
                    finding['file'] = rel_path
                    finding['scanned_at'] = scan_date
                    sev = finding.get('severity', 'UNKNOWN').upper()
                    if sev in severity_counts:
                        severity_counts[sev] += 1
                    else:
                        severity_counts['UNKNOWN'] += 1
                    all_findings.append(finding)

            total = sum(severity_counts.values())

            # Merge retained old findings with new findings
            merged_findings = retained_findings + all_findings
            merged_severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'UNKNOWN': 0}
            for _f in merged_findings:
                _sev = _f.get('severity', 'UNKNOWN').upper()
                if _sev in merged_severity_counts:
                    merged_severity_counts[_sev] += 1
                else:
                    merged_severity_counts['UNKNOWN'] += 1
            merged_total  = sum(merged_severity_counts.values())
            merged_files  = sorted(set(existing_report.get('files_scanned', [])) | current_rel_paths)
            first_scanned = existing_report.get('first_scanned', scan_date)

            # Reassign so the rest of the code (terminal output + markdown) uses merged data
            all_findings    = merged_findings
            severity_counts = merged_severity_counts
            total           = merged_total

            # Print terminal table
            if all_findings:
                table_rows = []
                for f in all_findings:
                    sev = f.get('severity', 'UNKNOWN').upper()
                    line_start = f.get('affected_code_line_start', '')
                    line_end = f.get('affected_code_line_end', '')
                    lines = f"{line_start}-{line_end}" if line_start != line_end else str(line_start)
                    cwe = ', '.join(f.get('cwe', [])) if isinstance(f.get('cwe'), list) else str(f.get('cwe', 'N/A'))
                    vuln = f.get('vuln', 'N/A')
                    vuln = vuln[:47] + '...' if len(vuln) > 50 else vuln
                    table_rows.append([f.get('file', 'N/A'), vuln, lines, color_severity(sev), cwe])

                print_findings_table(
                    table_rows,
                    headers=["File", "Vulnerability", "Lines", "Severity", "CWE"],
                )
                print(f"\n{Fore.YELLOW}Total vulnerabilities found: {total} (Breakdown: {severity_counts}){Style.RESET_ALL}")
            else:
                print(f"{Fore.GREEN}No vulnerabilities found.{Style.RESET_ALL}")

            # Save merged JSON report
            json_report = {
                'first_scanned':  first_scanned,
                'last_updated':   scan_date,
                'files_scanned':  merged_files,
                'total_findings': total,
                'severity_counts': severity_counts,
                'findings':       all_findings,
            }
            with open(json_path, 'w', encoding='utf-8') as jf:
                json.dump(json_report, jf, indent=2)

            # Build professional Markdown report
            def _sev_badge(sev):
                badges = {
                    'CRITICAL': '🔴 CRITICAL',
                    'HIGH':     '🟠 HIGH',
                    'MEDIUM':   '🟡 MEDIUM',
                    'LOW':      '🟢 LOW',
                    'UNKNOWN':  '⚪ UNKNOWN',
                }
                return badges.get(sev.upper(), sev)

            def _overall_risk(counts):
                for level in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                    if counts.get(level, 0) > 0:
                        return level
                return 'NONE'

            def _extract_cwe_id(cwe_str):
                """Extract 'CWE-306' from 'CWE-306: Some Description'."""
                import re as _re
                m = _re.match(r'(CWE-\d+)', str(cwe_str))
                return m.group(1) if m else cwe_str

            def _format_cwe_list(cwe_raw):
                """Return clean CWE IDs and full descriptions from the raw list."""
                if not isinstance(cwe_raw, list) or not cwe_raw:
                    return 'N/A', []
                ids   = [_extract_cwe_id(c) for c in cwe_raw]
                return ', '.join(ids), cwe_raw  # ids string, full entries list

            overall_risk       = _overall_risk(severity_counts)
            files_scanned_list = merged_files

            # Group findings by severity
            grouped = {'CRITICAL': [], 'HIGH': [], 'MEDIUM': [], 'LOW': [], 'UNKNOWN': []}
            for finding in all_findings:
                sev = finding.get('severity', 'UNKNOWN').upper()
                grouped.setdefault(sev, []).append(finding)

            risk_icon = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢', 'NONE': '✅'}.get(overall_risk, '')

            md = []

            # ── Header ─────────────────────────────────────────────────────────────
            md += [
                '# AquilaX Security Report',
                '',
                '> AI-Powered Code Security Analysis — [aquilax.ai](https://aquilax.ai)',
                '',
                '---',
                '',
            ]

            # ── Scan Overview ───────────────────────────────────────────────────────
            md += [
                '## Scan Overview',
                '',
                '| | |',
                '|---|---|',
                f'| **Last Updated** | {scan_date} |',
                f'| **First Scanned** | {first_scanned} |',
                f'| **Files in Report** | {len(merged_files)} |',
                f'| **Total Findings** | {total} |',
                f'| **Risk Level** | {risk_icon} {overall_risk} |',
                '',
                '---',
                '',
            ]

            # ── Severity Summary ────────────────────────────────────────────────────
            md += [
                '## Severity Summary',
                '',
                '| Severity | Count | % of Total |',
                '|----------|------:|-----------:|',
            ]
            for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']:
                count = severity_counts.get(sev, 0)
                pct   = f'{round(count / total * 100)}%' if total > 0 and count > 0 else '—'
                md.append(f'| {_sev_badge(sev)} | {count} | {pct} |')
            md += ['', '---', '']

            # ── Files Analyzed ──────────────────────────────────────────────────────
            md += [
                '## Files Analyzed',
                '',
                '| File | Findings |',
                '|------|------:|',
            ]
            for fp in sorted(files_scanned_list):
                fc = sum(1 for f in all_findings if f.get('file') == fp)
                status = str(fc) if fc > 0 else '✅ Clean'
                md.append(f'| `{fp}` | {status} |')
            md += ['', '---', '']

            # ── Findings ────────────────────────────────────────────────────────────
            if all_findings:
                md += ['## Findings', '']
                global_idx = 1
                for sev_level in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']:
                    level_findings = grouped.get(sev_level, [])
                    if not level_findings:
                        continue
                    md += [f'### {_sev_badge(sev_level)}', '']
                    for finding in level_findings:
                        sev        = finding.get('severity', 'UNKNOWN').upper()
                        line_start = finding.get('affected_code_line_start', '')
                        line_end   = finding.get('affected_code_line_end', '')
                        lines      = f'{line_start}–{line_end}' if str(line_start) != str(line_end) else str(line_start)
                        cwe_ids, cwe_full = _format_cwe_list(finding.get('cwe', []))
                        cves_raw   = finding.get('cves', [])
                        cves       = ', '.join(cves_raw) if cves_raw else '—'
                        vuln_title = finding.get('vuln', 'N/A')

                        md += [
                            f'#### {global_idx}. {vuln_title}',
                            '',
                            '| Property | Value |',
                            '|----------|-------|',
                            f'| **File** | `{finding.get("file", "N/A")}` |',
                            f'| **Line(s)** | {lines} |',
                            f'| **Severity** | {_sev_badge(sev)} |',
                            f'| **Confidence** | {finding.get("confidence", "N/A")} |',
                            f'| **Impact** | {finding.get("impact", "N/A")} |',
                            f'| **Likelihood** | {finding.get("likelihood", "N/A")} |',
                            f'| **CWE** | {cwe_ids} |',
                            f'| **CVEs** | {cves} |',
                            f'| **Rule ID** | {finding.get("rule_id", "N/A")} |',
                            '',
                            '**Description**',
                            '',
                            f'{finding.get("message", "N/A")}',
                            '',
                            '**Recommendation**',
                            '',
                            f'{finding.get("recommendation", "N/A")}',
                        ]

                        # Inline CWE details if the API returned full descriptions
                        if cwe_full and any(':' in str(c) for c in cwe_full):
                            md += ['', '**CWE Details**', '']
                            for entry in cwe_full:
                                cid = _extract_cwe_id(str(entry))
                                num = cid.replace('CWE-', '')
                                desc = str(entry).split(':', 1)[1].strip() if ':' in str(entry) else str(entry)
                                md.append(f'- [{cid}](https://cwe.mitre.org/data/definitions/{num}.html) — {desc}')

                        md += ['', '---', '']
                        global_idx += 1
            else:
                md += [
                    '## Findings',
                    '',
                    '✅ No vulnerabilities were detected during this scan.',
                    '',
                    '---',
                    '',
                ]

            # ── Footer ──────────────────────────────────────────────────────────────
            md += [
                '> **Disclaimer:** This report was generated automatically. '
                'Results should be reviewed by a qualified security professional. '
                'Validate findings in the context of your application before remediation.',
                '',
                f'*Generated on {scan_date} by [AquilaX](https://aquilax.ai)*',
            ]

            md_path = os.path.join(aquilax_dir, 'aquilax_ai_findings.md')
            with open(md_path, 'w', encoding='utf-8') as mf:
                mf.write('\n'.join(md))

            print(f"\nReports saved to:")
            print(f"  {Fore.CYAN}{os.path.relpath(md_path)}{Style.RESET_ALL}")
            print(f"  {Fore.CYAN}{os.path.relpath(json_path)}{Style.RESET_ALL}")

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
                scan_details = client.get_scan_by_id(org_id, group_id, args.scan_id)

                if not scan_details or "scan" not in scan_details:
                    print("No scan details found.")
                    return

                scan_info = scan_details.get("scan", {})
                results = scan_info.get("results", [])
                output_format = args.format or "table"

                if output_format == "json":
                    print(json.dumps(scan_details, indent=4))

                else:
                    print("\n")
                    print(f"Git URI: {scan_info.get('git_uri')}")
                    print(f"Branch: {scan_info.get('branch')}")
                    print(f"Scanners Used: {', '.join([scanner for scanner, used in scan_info.get('scanners', {}).items() if used])}")
                    print("\nResults:")

                    if not results:
                        print("No findings for this scan.")
                        return

                    all_findings, severity_counts, total_findings = parse_and_display_findings(scan_details, org_id, group_id)

                    if not all_findings:
                        print("No findings across all scanners.")
                        return

                    print_findings_table(
                        all_findings,
                        headers=["Scanner", "Path", "Vulnerability", "Severity", "CWE", "OWASP"],
                    )
                    print(f"{Fore.YELLOW}Total vulnerabilities found: {total_findings} (Breakdown: {severity_counts}){Style.RESET_ALL}")

    except ValueError as ve:
        print(ve)

    except Exception as e:
        logger.error(f"Error occurred: {str(e)}")

if __name__ == "__main__":
    main()