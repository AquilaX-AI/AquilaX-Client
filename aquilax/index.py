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
        ("fix <path>",         "AI-powered fix for vulnerabilities found by analyze"),
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

    # Fix command
    fix_parser = subparsers.add_parser('fix', help='AI-powered fix for vulnerabilities found by analyze')
    fix_parser.add_argument('target', help='File or directory to fix (e.g., app.py or .)')
    fix_parser.add_argument('--org-id', help='Organization ID')
    fix_parser.add_argument('--group-id', help='Group ID')
    fix_parser.add_argument('--auto', action='store_true',
                            help='Apply all fixes without confirmation prompts')
    fix_parser.add_argument('--dry-run', action='store_true',
                            help='Preview fixes without modifying files')
    fix_parser.add_argument('--severity', choices=['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
                            default=None,
                            help='Only fix findings at or above this severity level')

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

                            print_thresholds_and_fail_check(severity_counts, total_findings, client, org_id, group_id, args.fail_on_vulns, status)

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

                print_thresholds_and_fail_check(severity_counts, total_findings, client, org_id, group_id, args.fail_on_vulns, status)

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

        elif args.command == 'fix':
            import difflib
            import datetime

            org_id   = args.org_id   or config.get('org_id')
            group_id = args.group_id or config.get('group_id')

            if not org_id:
                print("Organization ID is not set. Please provide it using --org-id or set a default using --set-org.")
                return
            if not group_id:
                print("Group ID is not set. Please provide it using --group-id or set a default using --set-group.")
                return

            target     = os.path.abspath(args.target)
            target_dir = target if os.path.isdir(target) else os.path.dirname(target)

            # Set up .aquilax dirs (create if not exist)
            aquilax_dir = os.path.join(target_dir, '.aquilax')
            data_dir    = os.path.join(aquilax_dir, 'data')
            os.makedirs(data_dir, exist_ok=True)

            fix_date  = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            anal_path = os.path.join(data_dir, 'aquilax_ai_findings.json')
            fix_path  = os.path.join(data_dir, 'fix.json')

            # ── Collect files in scope ─────────────────────────────────────────
            _CODE_EXT = {
                '.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.go', '.rb', '.php',
                '.cs', '.cpp', '.c', '.h', '.hpp', '.rs', '.swift', '.kt', '.scala',
                '.sh', '.bash', '.yml', '.yaml', '.tf', '.hcl', '.html', '.css', '.sql', '.xml'
            }
            _SKIP_DIRS = {
                '.git', 'node_modules', '__pycache__', '.aquilax', 'venv', '.venv',
                'dist', 'build', '.tox', 'env', 'eggs', '.eggs', 'site-packages',
                '.pytest_cache', '.mypy_cache'
            }
            _MAX_SIZE = 1 * 1024 * 1024

            files_in_scope = []
            if os.path.isfile(target):
                files_in_scope = [target]
            elif os.path.isdir(target):
                for _root, _dirs, _fnames in os.walk(target):
                    _dirs[:] = [d for d in _dirs if d not in _SKIP_DIRS]
                    for _fname in _fnames:
                        _, _ext = os.path.splitext(_fname)
                        if _ext.lower() in _CODE_EXT or _fname in ('Dockerfile', 'Makefile'):
                            _fp = os.path.join(_root, _fname)
                            if os.path.getsize(_fp) <= _MAX_SIZE:
                                files_in_scope.append(_fp)
            else:
                print(f"Target not found: {args.target}")
                return

            if not files_in_scope:
                print("No supported code files found.")
                return

            scope_rel = {os.path.relpath(f, target_dir) for f in files_in_scope}

            # ── Load existing findings; auto-analyze missing files ─────────────
            existing_anal = {}
            if os.path.exists(anal_path):
                try:
                    with open(anal_path, 'r', encoding='utf-8') as _f:
                        existing_anal = json.load(_f)
                except Exception:
                    existing_anal = {}

            already_scanned = set(existing_anal.get('files_scanned', []))
            unanalyzed      = [f for f in files_in_scope
                               if os.path.relpath(f, target_dir) not in already_scanned]

            if unanalyzed:
                print(f"  {Fore.CYAN}◆ Scanning{Style.RESET_ALL}  {len(unanalyzed)} file(s) not yet analyzed — running analysis first\n")
                _new_findings   = []
                _unanalyzed_rel = {os.path.relpath(f, target_dir) for f in unanalyzed}

                for _fpath in unanalyzed:
                    _rp = os.path.relpath(_fpath, target_dir)
                    try:
                        with open(_fpath, 'r', encoding='utf-8', errors='ignore') as _f:
                            _code = _f.read()
                    except Exception as _e:
                        logger.warning(f"Could not read {_fpath}: {_e}")
                        continue
                    if not _code.strip():
                        continue
                    try:
                        _file_findings = client.scan_code(org_id, group_id, _code)
                    except requests.HTTPError as _he:
                        if _he.response.status_code == 400:
                            continue
                        logger.error(f"Scan error {_rp}: {_he}")
                        continue
                    except Exception as _e:
                        logger.error(f"Scan error {_rp}: {_e}")
                        continue
                    for _ff in _file_findings:
                        _ff['file']       = _rp
                        _ff['scanned_at'] = fix_date
                        _new_findings.append(_ff)

                # Merge into findings report
                _retained_a = [_f for _f in existing_anal.get('findings', [])
                               if _f.get('file') not in _unanalyzed_rel]
                _merged_a   = _retained_a + _new_findings
                _merged_files_a = sorted(already_scanned | _unanalyzed_rel)
                _merged_sev_a   = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'UNKNOWN': 0}
                for _f in _merged_a:
                    _s = _f.get('severity', 'UNKNOWN').upper()
                    _merged_sev_a[_s] = _merged_sev_a.get(_s, 0) + 1

                existing_anal = {
                    'first_scanned': existing_anal.get('first_scanned', fix_date),
                    'last_updated':  fix_date,
                    'files_scanned': _merged_files_a,
                    'total_findings': sum(_merged_sev_a.values()),
                    'severity_counts': _merged_sev_a,
                    'findings': _merged_a,
                }
                with open(anal_path, 'w', encoding='utf-8') as _f:
                    json.dump(existing_anal, _f, indent=2)

                _vuln_count = len(_new_findings)
                print(f"  {Fore.GREEN}✓ Analysis done{Style.RESET_ALL}  {_vuln_count} finding(s) found\n")

            report       = existing_anal
            all_findings = report.get('findings', [])

            # ── Filter findings ────────────────────────────────────────────────
            SEVERITY_RANK = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'UNKNOWN': 0}
            min_rank = SEVERITY_RANK.get(args.severity, 0) if args.severity else 0

            candidates = [f for f in all_findings if f.get('file') in scope_rel]

            findings_to_fix = [
                f for f in candidates
                if f.get('status') != 'fixed'
                and SEVERITY_RANK.get(f.get('severity', 'UNKNOWN').upper(), 0) >= min_rank
            ]

            if not findings_to_fix:
                print(f"  {Fore.GREEN}✓ Nothing to fix{Style.RESET_ALL}  No unfixed findings for '{args.target}'")
                return

            dry_tag = f"{Fore.CYAN}[dry-run]{Style.RESET_ALL} " if args.dry_run else ''
            print(f"  {Fore.CYAN}◆ Fixing{Style.RESET_ALL}  {dry_tag}{len(findings_to_fix)} vulnerability(ies) in {Style.BRIGHT}{args.target}{Style.RESET_ALL}\n")

            # ── Helpers ────────────────────────────────────────────────────────
            FIX_SYSTEM_PROMPT = (
                "You are a security code fixer. Fix the exact vulnerability described. "
                "Return ONLY the corrected replacement code — no explanations, no markdown "
                "fences, no added comments unless they were in the original code."
            )

            def _strip_fences(text):
                text = text.strip()
                if text.startswith('```'):
                    lines = text.splitlines()
                    lines = lines[1:] if lines and lines[0].startswith('```') else lines
                    lines = lines[:-1] if lines and lines[-1].strip() == '```' else lines
                    text = '\n'.join(lines)
                return text

            def _diff_lines(original_lines, fixed_lines, rel_path):
                return list(difflib.unified_diff(
                    original_lines, fixed_lines,
                    fromfile=f'a/{rel_path}', tofile=f'b/{rel_path}', lineterm=''
                ))

            def _print_diff(diff):
                if not diff:
                    print(f"  {Fore.YELLOW}(no changes in diff){Style.RESET_ALL}")
                    return
                for line in diff:
                    if line.startswith('+++') or line.startswith('---'):
                        print(f"{Style.BRIGHT}{line}{Style.RESET_ALL}")
                    elif line.startswith('+'):
                        print(f"{Fore.GREEN}{line}{Style.RESET_ALL}")
                    elif line.startswith('-'):
                        print(f"{Fore.RED}{line}{Style.RESET_ALL}")
                    elif line.startswith('@@'):
                        print(f"{Fore.CYAN}{line}{Style.RESET_ALL}")
                    else:
                        print(line)

            def _lang_hint(filename):
                _ext_map = {
                    '.py': 'python', '.js': 'javascript', '.ts': 'typescript',
                    '.java': 'java', '.go': 'go', '.rb': 'ruby', '.php': 'php',
                    '.cs': 'csharp', '.cpp': 'cpp', '.c': 'c', '.rs': 'rust',
                    '.sh': 'bash', '.yaml': 'yaml', '.yml': 'yaml', '.sql': 'sql',
                }
                _, _e = os.path.splitext(filename)
                return _ext_map.get(_e.lower(), '')

            # ── Fix loop ───────────────────────────────────────────────────────
            applied        = 0
            skipped        = 0
            failed         = 0
            modified_files = set()
            skip_all       = False
            applied_fixes  = []   # records for fix.md / fix.json
            w              = min(_term_width(), 70)

            for idx, finding in enumerate(findings_to_fix, 1):
                rel_path   = finding.get('file', '')
                file_path  = os.path.join(target_dir, rel_path)
                sev        = finding.get('severity', 'UNKNOWN').upper()
                vuln_title = finding.get('vuln', 'N/A')
                line_start = finding.get('affected_code_line_start', 0)
                line_end   = finding.get('affected_code_line_end',   0)
                cwe_raw    = finding.get('cwe', [])
                cwe_str    = ', '.join(cwe_raw) if isinstance(cwe_raw, list) else str(cwe_raw)

                _lines_str = f'line {line_start}' if line_start == line_end else f'lines {line_start}–{line_end}'
                print(f"  {'─' * (w - 2)}")
                print(f"  {Style.BRIGHT}[{idx}/{len(findings_to_fix)}]{Style.RESET_ALL}  {color_severity(sev)}  {vuln_title[:55]}")
                print(f"  {Style.DIM}{rel_path}  ·  {_lines_str}{Style.RESET_ALL}")

                if skip_all:
                    print(f"  {Fore.YELLOW}↷ skipped{Style.RESET_ALL}\n")
                    skipped += 1
                    continue

                # Read source file
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as src:
                        original_content = src.read()
                except Exception as e:
                    print(f"  {Fore.RED}✗ cannot read file: {e}{Style.RESET_ALL}\n")
                    failed += 1
                    continue

                original_lines = original_content.splitlines(keepends=True)

                # Build prompt context — affected lines + N surrounding lines
                CONTEXT_LINES = 10
                has_lines = line_start > 0 and line_end > 0
                if has_lines:
                    snippet_lines      = original_lines[line_start - 1 : line_end]
                    vulnerable_snippet = ''.join(snippet_lines)

                    ctx_start      = max(0, line_start - 1 - CONTEXT_LINES)
                    ctx_end        = min(len(original_lines), line_end + CONTEXT_LINES)
                    context_before = ''.join(original_lines[ctx_start : line_start - 1])
                    context_after  = ''.join(original_lines[line_end  : ctx_end])

                    line_context = (
                        f"Affected lines: {line_start}–{line_end}\n\n"
                        f"Context before (lines {ctx_start + 1}–{line_start - 1}):\n{context_before}\n"
                        f"Vulnerable code (lines {line_start}–{line_end}):\n{vulnerable_snippet}\n"
                        f"Context after (lines {line_end + 1}–{ctx_end}):\n{context_after}\n"
                    )
                    fix_instruction = (
                        f"Return ONLY the fixed replacement for lines {line_start}–{line_end}.\n"
                        "If the fix requires changes outside those lines, return the entire corrected file "
                        "prefixed with exactly: FULL_FILE:\n"
                    )
                else:
                    # No line info — send full file as fallback
                    line_context    = f"Full file content:\n{original_content}\n"
                    fix_instruction = (
                        "Return the entire corrected file prefixed with exactly: FULL_FILE:\n"
                    )

                user_prompt = (
                    f"File: {rel_path}\n"
                    f"Vulnerability: {vuln_title}\n"
                    f"Severity: {sev}\n"
                    f"CWE: {cwe_str}\n"
                    f"Description: {finding.get('message', '')}\n"
                    f"Recommendation: {finding.get('recommendation', '')}\n\n"
                    f"{line_context}\n"
                    f"{fix_instruction}"
                )

                # Call AI API
                try:
                    ai_result = client.ai_prompt(org_id, group_id, user_prompt, FIX_SYSTEM_PROMPT)
                except requests.HTTPError as http_err:
                    err_body = ''
                    try:
                        err_body = http_err.response.json().get('error', '')
                    except Exception:
                        pass
                    if 'Pro or Ultimate' in err_body or 'plan' in err_body.lower():
                        print(f"\n  {Fore.YELLOW}⚠  This feature requires a Pro or Ultimate plan.")
                        print(f"     Upgrade at https://aquilax.ai to unlock AI-powered fixes.{Style.RESET_ALL}\n")
                        return
                    logger.error(f"AI prompt HTTP error for {rel_path}: {http_err}")
                    print(f"  {Fore.RED}✗ API error{Style.RESET_ALL}  {Style.DIM}{http_err}{Style.RESET_ALL}\n")
                    failed += 1
                    continue
                except Exception as e:
                    logger.error(f"AI prompt error for {rel_path}: {e}")
                    print(f"  {Fore.RED}✗ error{Style.RESET_ALL}  {Style.DIM}{e}{Style.RESET_ALL}\n")
                    failed += 1
                    continue

                raw_response = ai_result.get('response', '')
                if not raw_response.strip():
                    print(f"  {Fore.YELLOW}↷ no response from AI — skipping{Style.RESET_ALL}\n")
                    skipped += 1
                    continue

                # Parse response — full file or line replacement
                cleaned = _strip_fences(raw_response)
                if cleaned.startswith('FULL_FILE:'):
                    fixed_content  = cleaned[len('FULL_FILE:'):].lstrip('\n')
                    fixed_lines    = fixed_content.splitlines(keepends=True)
                    full_file_mode = True
                else:
                    replacement    = cleaned
                    fixed_lines    = list(original_lines)
                    if has_lines:
                        replace_chunk  = replacement.splitlines(keepends=True)
                        # Ensure last line ends with newline
                        if replace_chunk and not replace_chunk[-1].endswith('\n'):
                            replace_chunk[-1] += '\n'
                        fixed_lines[line_start - 1 : line_end] = replace_chunk
                    else:
                        # No line info — treat as full file
                        fixed_lines    = replacement.splitlines(keepends=True)
                    full_file_mode = False
                    fixed_content  = ''.join(fixed_lines)

                # Build diff
                diff = _diff_lines(original_lines, fixed_lines, rel_path)

                if args.dry_run:
                    _print_diff(diff)
                    print()
                    print(f"  {Style.DIM}↷ dry-run — file not modified{Style.RESET_ALL}\n")
                    skipped += 1
                    continue

                # Confirm — show diff, then erase it after user responds
                if not args.auto:
                    _print_diff(diff)
                    print()
                    # count lines printed: diff lines (or 1 for "no changes") + 1 blank
                    diff_lines_count = (len(diff) if diff else 1) + 1
                    try:
                        choice = input(f"  {Style.BRIGHT}Apply fix?{Style.RESET_ALL}  {Style.DIM}[y/n/s=skip all]{Style.RESET_ALL}  ").strip().lower()
                    except (EOFError, KeyboardInterrupt):
                        choice = 'n'
                    # Erase diff + blank line + prompt line from terminal
                    for _ in range(diff_lines_count + 1):
                        print('\033[1A\033[2K', end='', flush=True)
                    if choice == 's':
                        skip_all = True
                        skipped += 1
                        print(f"  {Style.DIM}↷ skipped all{Style.RESET_ALL}\n")
                        continue
                    elif choice == 'n':
                        skipped += 1
                        print(f"  {Style.DIM}↷ skipped{Style.RESET_ALL}\n")
                        continue

                # Write patched file
                try:
                    with open(file_path, 'w', encoding='utf-8') as dst:
                        dst.write(fixed_content)
                    finding['status']   = 'fixed'
                    finding['fixed_at'] = fix_date
                    applied += 1
                    modified_files.add(rel_path)
                    print(f"  {Fore.GREEN}✓ fix applied{Style.RESET_ALL}  {Style.DIM}{rel_path}{Style.RESET_ALL}\n")

                    # Extract before/after snippet for report (up to 30 lines context)
                    if has_lines:
                        ctx_start = max(0, line_start - 1)
                        ctx_end   = min(len(original_lines), line_end)
                        before_snippet = ''.join(original_lines[ctx_start:ctx_end])
                        # fixed_lines may have different length after replacement
                        fixed_ctx_end = min(len(fixed_lines), ctx_start + (ctx_end - ctx_start) + 5)
                        after_snippet = ''.join(fixed_lines[ctx_start:fixed_ctx_end])
                    else:
                        before_snippet = original_content[:2000]
                        after_snippet  = fixed_content[:2000]

                    applied_fixes.append({
                        'file':           rel_path,
                        'vuln':           vuln_title,
                        'severity':       sev,
                        'cwe':            finding.get('cwe', []),
                        'message':        finding.get('message', ''),
                        'recommendation': finding.get('recommendation', ''),
                        'line_start':     line_start,
                        'line_end':       line_end,
                        'fixed_at':       fix_date,
                        'diff':           '\n'.join(diff),
                        'before_snippet': before_snippet,
                        'after_snippet':  after_snippet,
                    })
                except Exception as e:
                    logger.error(f"Failed to write fix to {file_path}: {e}")
                    print(f"  {Fore.RED}✗ failed to write{Style.RESET_ALL}  {Style.DIM}{e}{Style.RESET_ALL}\n")
                    failed += 1

            # ── Update aquilax_ai_findings.json ────────────────────────────────
            if applied > 0 and not args.dry_run:
                active     = [f for f in all_findings if f.get('status') != 'fixed']
                new_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'UNKNOWN': 0}
                for f in active:
                    s = f.get('severity', 'UNKNOWN').upper()
                    new_counts[s] = new_counts.get(s, 0) + 1
                report['total_findings']  = len(active)
                report['severity_counts'] = new_counts
                report['last_updated']    = fix_date
                try:
                    with open(anal_path, 'w', encoding='utf-8') as _jf:
                        json.dump(report, _jf, indent=2)
                except Exception as e:
                    logger.warning(f"Could not update findings JSON: {e}")

            # ── Save fix.json (incremental merge) ──────────────────────────────
            if applied_fixes and not args.dry_run:
                existing_fix = {}
                if os.path.exists(fix_path):
                    try:
                        with open(fix_path, 'r', encoding='utf-8') as _f:
                            existing_fix = json.load(_f)
                    except Exception:
                        existing_fix = {}

                _fixed_now       = {fx['file'] for fx in applied_fixes}
                _retained_fixes  = [fx for fx in existing_fix.get('fixes', [])
                                    if fx.get('file') not in _fixed_now]
                _merged_fixes    = _retained_fixes + applied_fixes
                _merged_fix_files = sorted(
                    set(existing_fix.get('files_fixed', [])) | _fixed_now
                )
                fix_report = {
                    'first_fixed':  existing_fix.get('first_fixed', fix_date),
                    'last_updated': fix_date,
                    'files_fixed':  _merged_fix_files,
                    'total_fixes':  len(_merged_fixes),
                    'fixes':        _merged_fixes,
                }
                try:
                    with open(fix_path, 'w', encoding='utf-8') as _f:
                        json.dump(fix_report, _f, indent=2)
                except Exception as e:
                    logger.warning(f"Could not write fix.json: {e}")
                    fix_report = {'fixes': _merged_fixes,
                                  'first_fixed': fix_date, 'last_updated': fix_date,
                                  'files_fixed': list(_fixed_now), 'total_fixes': len(_merged_fixes)}

                # ── Generate fix.md ────────────────────────────────────────────
                def _fix_sev_badge(sev):
                    return {'CRITICAL': '🔴 CRITICAL', 'HIGH': '🟠 HIGH',
                            'MEDIUM': '🟡 MEDIUM', 'LOW': '🟢 LOW'}.get(sev.upper(), f'⚪ {sev}')

                all_fix_entries = fix_report['fixes']
                _fix_md = [
                    '# AquilaX Fix Report',
                    '',
                    '> AI-Powered Security Fixes — [aquilax.ai](https://aquilax.ai)',
                    '',
                    '---',
                    '',
                    '## Overview',
                    '',
                    '| | |',
                    '|---|---|',
                    f'| **Last Updated** | {fix_date} |',
                    f'| **First Fixed** | {fix_report["first_fixed"]} |',
                    f'| **Total Fixes in Report** | {fix_report["total_fixes"]} |',
                    f'| **Files Modified** | {", ".join(f"`{f}`" for f in fix_report["files_fixed"])} |',
                    '',
                    '---',
                    '',
                ]

                # Severity breakdown of all fixes
                _fx_sev_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'UNKNOWN': 0}
                for _fx in all_fix_entries:
                    _s = _fx.get('severity', 'UNKNOWN').upper()
                    _fx_sev_counts[_s] = _fx_sev_counts.get(_s, 0) + 1

                _fix_md += [
                    '## Fixes by Severity',
                    '',
                    '| Severity | Count |',
                    '|----------|------:|',
                ]
                for _sv in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']:
                    _cnt = _fx_sev_counts.get(_sv, 0)
                    if _cnt > 0:
                        _fix_md.append(f'| {_fix_sev_badge(_sv)} | {_cnt} |')
                _fix_md += ['', '---', '', '## Fixes Applied', '']

                # Group by file
                _files_order = []
                _by_file = {}
                for _fx in all_fix_entries:
                    _fp = _fx.get('file', 'unknown')
                    if _fp not in _by_file:
                        _by_file[_fp] = []
                        _files_order.append(_fp)
                    _by_file[_fp].append(_fx)

                _global_idx = 1
                for _fp in _files_order:
                    _fix_md += [f'### `{_fp}`', '']
                    for _fx in _by_file[_fp]:
                        _sev       = _fx.get('severity', 'UNKNOWN').upper()
                        _ls        = _fx.get('line_start', 0)
                        _le        = _fx.get('line_end',   0)
                        _lines_str = f'{_ls}–{_le}' if _ls and _ls != _le else str(_ls or '—')
                        _cwe_raw   = _fx.get('cwe', [])
                        _cwe_str   = ', '.join(_cwe_raw) if isinstance(_cwe_raw, list) and _cwe_raw else '—'
                        _lang      = _lang_hint(_fp)

                        _fix_md += [
                            f'#### {_global_idx}. {_fx.get("vuln", "N/A")}',
                            '',
                            '| Property | Value |',
                            '|----------|-------|',
                            f'| **File** | `{_fp}` |',
                            f'| **Line(s)** | {_lines_str} |',
                            f'| **Severity** | {_fix_sev_badge(_sev)} |',
                            f'| **CWE** | {_cwe_str} |',
                            f'| **Fixed At** | {_fx.get("fixed_at", "—")} |',
                            '',
                            '**Issue**',
                            '',
                            f'{_fx.get("message", "—")}',
                            '',
                        ]

                        _before = _fx.get('before_snippet', '').rstrip()
                        _after  = _fx.get('after_snippet',  '').rstrip()
                        if _before or _after:
                            if _before:
                                _fix_md += [
                                    '**Before**',
                                    '',
                                    f'```{_lang}',
                                    _before,
                                    '```',
                                    '',
                                ]
                            if _after:
                                _fix_md += [
                                    '**After**',
                                    '',
                                    f'```{_lang}',
                                    _after,
                                    '```',
                                    '',
                                ]
                        elif _fx.get('diff'):
                            _fix_md += [
                                '**Diff**',
                                '',
                                '```diff',
                                _fx['diff'],
                                '```',
                                '',
                            ]

                        _fix_md += ['---', '']
                        _global_idx += 1

                _fix_md += [
                    '> **Disclaimer:** Fixes were generated automatically by AquilaX AI. '
                    'Review all changes before deploying to production.',
                    '',
                    f'*Report generated on {fix_date} by [AquilaX](https://aquilax.ai)*',
                ]

                md_fix_path = os.path.join(aquilax_dir, 'fix.md')
                try:
                    with open(md_fix_path, 'w', encoding='utf-8') as _mf:
                        _mf.write('\n'.join(_fix_md))
                except Exception as e:
                    logger.warning(f"Could not write fix.md: {e}")
                    md_fix_path = None

            # ── Summary ────────────────────────────────────────────────────────
            print(Style.BRIGHT + '─' * w + Style.RESET_ALL)
            print(f"  {Fore.GREEN}✓ {applied} applied{Style.RESET_ALL}"
                  f"  {Style.DIM}·{Style.RESET_ALL}"
                  f"  {Style.DIM}↷ {skipped} skipped{Style.RESET_ALL}"
                  + (f"  {Style.DIM}·{Style.RESET_ALL}  {Fore.RED}✗ {failed} failed{Style.RESET_ALL}" if failed else ""))
            if modified_files:
                print(f"  {Style.DIM}files  {', '.join(sorted(modified_files))}{Style.RESET_ALL}")
            print(Style.BRIGHT + '─' * w + Style.RESET_ALL)
            if applied > 0 and not args.dry_run:
                print(f"  {Style.DIM}report  {os.path.relpath(md_fix_path)}{Style.RESET_ALL}")
                print(f"  {Style.DIM}data    {os.path.relpath(fix_path)}{Style.RESET_ALL}")
                print()
                print(f"  {Style.DIM}run 'aquilax analyze {args.target}' to verify remaining issues{Style.RESET_ALL}")
            print()

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