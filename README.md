<div align="center">

# 🛡️ AquilaX CLI

**Enterprise-Grade Application Security Testing from Your Terminal**

[![PyPI version](https://badge.fury.io/py/aquilax.svg)](https://badge.fury.io/py/aquilax)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.6+-blue.svg)](https://www.python.org/downloads/)

[Installation](#-installation) • [Quick Start](#-quick-start) • [Features](#-features) • [Local Analysis](#-local-code-analysis) • [AI Fix](#-ai-powered-fix) • [Documentation](#-documentation) • [Support](#-support)

</div>

---

## 📖 Overview

**AquilaX CLI** is a professional command-line tool that integrates with the **AquilaX Application Security Platform**. It helps developers and security teams find and fix security issues early in the development process, right from their terminal or CI/CD pipeline.

Whether you're a developer checking code before commit, a security professional running automated scans, or a DevOps engineer integrating security into pipelines, AquilaX CLI provides enterprise-level security scanning with an easy-to-use interface.

---

## ✨ Key Features

### 🔍 Multiple Security Scanners
Scan your code for various security vulnerabilities with specialized scanners:

- 🔐 **PII Scanner** - Find personally identifiable information that shouldn't be in your code
- 🔑 **Secret Scanner** - Detect exposed passwords, API keys, and authentication tokens
- ☁️ **IaC Scanner** - Check Infrastructure as Code files (Terraform, CloudFormation, etc.)
- 🛡️ **SAST Scanner** - Analyze source code for security vulnerabilities
- 📦 **SCA Scanner** - Find known vulnerabilities in your dependencies and libraries
- 🐳 **Container Scanner** - Scan Docker images and containers for security issues
- 🖼️ **Image Scanner** - Analyze docker images in your repository
- ⚙️ **CI/CD Scanner** - Review pipeline configurations for security best practices

### 🚀 Easy CI/CD Integration
- **Works with Any Pipeline** - Compatible with GitHub Actions, GitLab CI, Jenkins, Azure DevOps, and more
- **Configurable Rules** - Set your own security thresholds and policies
- **Automatic Scanning** - Run scans automatically on every code commit or deployment
- **Build Control** - Automatically fail builds when security issues are found

### 📊 Easy-to-Read Results
- **Live Updates** - Watch your scan progress in real-time
- **Color-Coded Severity** - Quickly identify Critical, High, Medium, and Low severity issues
- **Clean Tables** - Results displayed in easy-to-read tables
- **Multiple Formats** - Export as JSON for automation or view in formatted tables

### 🎯 Flexible Setup
- **Multiple Teams** - Work with different organizations and project groups
- **Save Preferences** - Store your frequently used settings to save time
- **On-Premise Ready** - Works with self-hosted AquilaX installations
- **Any Branch** - Scan any Git branch, not just main

### 🔎 Local Code Analysis
Scan local files and directories instantly — no Git repository required:

- **Single File** - Analyze one file at a time (`aquilax analyze app.py`)
- **Entire Project** - Scan all code files recursively (`aquilax analyze .`)
- **Incremental Reports** - Results are merged into a persistent report; re-scanning a file updates only that file's findings
- **AI-Powered Findings** - Each finding includes severity, CWE references, description, and remediation guidance
- **Dual Output** - Generates a professional Markdown report and a structured JSON file in `.aquilax/`

### 🔧 AI-Powered Fix
Automatically fix vulnerabilities found by `analyze` using AI:

- **Single File** - Fix one file at a time (`aquilax fix app.py`)
- **Entire Project** - Fix all files in the report (`aquilax fix .`)
- **Auto Mode** - Apply all fixes without prompts (`--auto`)
- **Dry Run** - Preview the diff without modifying any files (`--dry-run`)
- **Severity Filter** - Fix only HIGH and above (`--severity HIGH`)
- **Context-Aware** - AI receives the affected lines plus surrounding context for accurate fixes
- **Fix Reports** - Generates `.aquilax/fix.md` and `.aquilax/data/fix.json` with before/after diffs

### 📈 Detailed Security Reports
- **Industry Standards** - See how issues map to OWASP Top 10 security risks
- **CWE References** - Get standard security weakness classifications
- **Clear Categorization** - Understand exactly what types of vulnerabilities were found
- **Web Dashboard** - View full details and trends in your online dashboard

---

## 🚀 Installation

### From PyPI (Recommended)

```bash
pip install aquilax
```

### From Source

```bash
git clone https://github.com/AquilaX-AI/AquilaX-Client.git
cd AquilaX-Client
pip install -e .
```

### Verify Installation

```bash
aquilax --version
```

---

## 🎯 Quick Start

### 1. Authentication

Login with your AquilaX API token:

```bash
aquilax login YOUR_API_TOKEN
```

For on-premise installations:

```bash
aquilax login YOUR_API_TOKEN --server https://your-aquilax-instance.com
```

### 2. Configure Defaults

Set your default organization and group to streamline commands:

```bash
aquilax --set-org YOUR_ORG_ID
aquilax --set-group YOUR_GROUP_ID
```

### 3. Analyze Local Code

Scan a local file or your entire project instantly:

```bash
# Scan a single file
aquilax analyze app.py

# Scan your entire project
aquilax analyze .
```

Reports are saved to `.aquilax/aquilax_ai_findings.md` and `.aquilax/data/aquilax_ai_findings.json`.

### 4. Fix Vulnerabilities with AI

Automatically fix findings from the previous `analyze` run:

```bash
# Fix a single file (interactive — confirm each fix)
aquilax fix app.py

# Fix everything without prompts
aquilax fix . --auto

# Preview fixes without modifying files
aquilax fix app.py --dry-run
```

Fix reports are saved to `.aquilax/fix.md` and `.aquilax/data/fix.json`.

### 5. Run a Remote Repository Scan

Start a security scan with real-time monitoring:

```bash
aquilax scan https://github.com/your-org/your-repo --sync
```

---

## 📚 Documentation

### Commands Overview

#### 🔐 Authentication & Configuration

##### Login
Authenticate with the AquilaX platform:

```bash
aquilax login <token> [--server <url>]
```

**Options:**
- `<token>` - Your AquilaX API authentication token
- `--server` - (Optional) Custom server URL for on-premise installations (default: `https://aquilax.ai`)

**Example:**
```bash
aquilax login eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
aquilax login my_token --server https://aquilax.mycompany.com
```

##### Logout
Remove stored authentication credentials:

```bash
aquilax logout
```

##### Set Default Organization
Configure your default organization ID:

```bash
aquilax --set-org <org_id>
```

##### Set Default Group
Configure your default group ID:

```bash
aquilax --set-group <group_id>
```

---

#### 🔍 Scanning Commands

##### Standard Scan
Initiate a comprehensive security scan on a Git repository:

```bash
aquilax scan <git_uri> [options]
```

**Options:**
| Option | Description | Default |
|--------|-------------|---------|
| `--scanners` | List of scanners to use | All 8 scanners |
| `--branch` | Git branch to scan | `main` |
| `--sync` | Enable real-time monitoring | Disabled |
| `--format` | Output format (`json` or `table`) | `table` |

**Examples:**
```bash
# Basic scan with all scanners
aquilax scan https://github.com/myorg/myrepo

# Scan specific branch with real-time updates
aquilax scan https://github.com/myorg/myrepo --branch develop --sync

# Run only specific scanners
aquilax scan https://github.com/myorg/myrepo --scanners secret_scanner sast_scanner

# Output results as JSON
aquilax scan https://github.com/myorg/myrepo --format json
```

##### CI/CD Scan
Specialized scan command optimized for CI/CD pipelines:

```bash
aquilax ci-scan <git_uri> [options]
```

**Options:**
| Option | Description | Default |
|--------|-------------|---------|
| `--org-id` | Organization ID (overrides default) | From config |
| `--group-id` | Group ID (overrides default) | From config |
| `--branch` | Git branch to scan | `main` |
| `--sync` | Enable real-time monitoring | Disabled |
| `--fail-on-vulns` | Fail pipeline if any vulnerabilities found | Disabled |
| `--format` | Output format (`json` or `table`) | `table` |
| `--output-dir` | Directory for PDF reports | Current directory |
| `--save-pdf` | Save PDF report locally | Disabled |

**CI/CD Examples:**

```bash
# Basic CI/CD scan
aquilax ci-scan https://github.com/myorg/myrepo

# Fail build if vulnerabilities exceed thresholds
aquilax ci-scan https://github.com/myorg/myrepo --fail-on-vulns

# CI/CD with custom org/group and JSON output
aquilax ci-scan https://github.com/myorg/myrepo \
  --org-id 507f1f77bcf86cd799439011 \
  --group-id 507f1f77bcf86cd799439012 \
  --format json
```

**GitLab CI Example:**
```yaml
security_scan:
  stage: test
  script:
    - pip install aquilax
    - aquilax login $AQUILAX_TOKEN
    - aquilax ci-scan $CI_REPOSITORY_URL --branch $CI_COMMIT_BRANCH --fail-on-vulns
```

**GitHub Actions Example:**
```yaml
- name: AquilaX Security Scan
  run: |
    pip install aquilax
    aquilax login ${{ secrets.AQUILAX_TOKEN }}
    aquilax ci-scan ${{ github.repository }} --fail-on-vulns
```

---

#### 🔎 Local Code Analysis

Scan local files or directories for security vulnerabilities using AI-powered analysis. No Git repository required.

```bash
aquilax analyze <path> [options]
```

**Options:**
| Option | Description | Default |
|--------|-------------|---------|
| `--org-id` | Organization ID (overrides default) | From config |
| `--group-id` | Group ID (overrides default) | From config |

**Examples:**
```bash
# Scan a single file
aquilax analyze app.py

# Scan your entire project directory
aquilax analyze .

# Scan a subdirectory
aquilax analyze src/

# Override org/group for this scan
aquilax analyze . --org-id <org_id> --group-id <group_id>
```

**Supported File Types:**

Python, JavaScript, TypeScript, Java, Go, Ruby, PHP, C/C++, C#, Rust, Swift, Kotlin, Scala, Shell, YAML, Terraform, HCL, HTML, CSS, SQL, XML, Dockerfile, Makefile, and more.

**Skipped Directories:**

`.git`, `node_modules`, `__pycache__`, `.aquilax`, `venv`, `dist`, `build`, and other common non-source directories are automatically excluded.

---

### 📁 Local Code Analysis — Incremental Reports

Each `analyze` run merges results into a **persistent, cumulative report** stored inside your project:

```
.aquilax/
├── aquilax_ai_findings.md        ← Professional markdown security report
└── data/
    └── aquilax_ai_findings.json  ← Full structured JSON data
```

**Merge Behavior:**

| Scenario | Result |
|----------|--------|
| First scan (`analyze app.py`) | Creates a fresh report |
| New file (`analyze server.py`) | Appends `server.py` findings; `app.py` findings are preserved |
| Re-scan same file (`analyze app.py` again) | Refreshes only `app.py` findings; all other files remain unchanged |

This means you can build up a complete picture of your project's security posture one file (or directory) at a time.

**Report Contents — `aquilax_ai_findings.md`:**

| Section | Description |
|---------|-------------|
| Scan Overview | Last updated, first scanned, total files, risk level |
| Severity Summary | Count and percentage breakdown per severity level |
| Files Analyzed | Per-file finding count |
| Detailed Findings | Full finding details grouped by severity (CRITICAL → HIGH → MEDIUM → LOW) |
| CWE Details | Inline MITRE CWE references with links |

Each finding includes:
- **Severity** — CRITICAL / HIGH / MEDIUM / LOW
- **File & line numbers** — Exact location of the vulnerability
- **Confidence, Impact, Likelihood** — Risk assessment dimensions
- **CWE references** — Linked to the MITRE CWE database
- **Description** — What the vulnerability is and why it's dangerous
- **Recommendation** — Specific remediation guidance
- **Scan timestamp** — When this file was last scanned

**Report Contents — `aquilax_ai_findings.json`:**

```json
{
  "first_scanned": "2026-03-17 10:00:00",
  "last_updated":  "2026-03-17 14:32:00",
  "files_scanned": ["app.py", "server.py"],
  "total_findings": 3,
  "severity_counts": { "CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 0, "UNKNOWN": 0 },
  "findings": [
    {
      "file": "app.py",
      "scanned_at": "2026-03-17 14:32:00",
      "vuln": "SQL Injection: query = \"SELECT * FROM users WHERE id = '\" + user_input",
      "severity": "HIGH",
      "confidence": "HIGH",
      "impact": "HIGH",
      "likelihood": "MEDIUM",
      "cwe": ["CWE-89: Improper Neutralization of Special Elements used in an SQL Command"],
      "message": "SQL injection vulnerability due to direct concatenation of user input.",
      "recommendation": "Use parameterized queries or an ORM to prevent SQL injection.",
      "affected_code_line_start": 12,
      "affected_code_line_end": 12
    }
  ]
}
```

---

#### 🔧 AI-Powered Fix

Automatically fix vulnerabilities identified by `analyze`. The AI receives the affected lines plus surrounding context to generate precise, targeted fixes.

> **Requires:** Run `aquilax analyze <path>` first to generate findings.

```bash
aquilax fix <path> [options]
```

**Options:**
| Option | Description | Default |
|--------|-------------|---------|
| `--org-id` | Organization ID (overrides default) | From config |
| `--group-id` | Group ID (overrides default) | From config |
| `--auto` | Apply all fixes without confirmation prompts | Disabled |
| `--dry-run` | Preview diffs without modifying any files | Disabled |
| `--severity` | Only fix findings at or above this level (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`) | All severities |

**Examples:**
```bash
# Fix a single file — confirm each fix interactively
aquilax fix app.py

# Fix all files in the project — no prompts
aquilax fix . --auto

# Preview what would be changed without touching files
aquilax fix app.py --dry-run

# Only fix CRITICAL and HIGH findings
aquilax fix . --severity HIGH --auto

# Override org/group for this run
aquilax fix app.py --org-id <org_id> --group-id <group_id>
```

**Interactive mode:**

When run without `--auto`, each fix is shown as a diff and you are prompted:

```
  [1/2]  HIGH  SQL Injection: cursor.execute(f"SELECT * FROM users...")
  app.py  ·  line 12
--- a/app.py
+++ b/app.py
@@ -10,4 +10,4 @@
-    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
+    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))

  Apply fix?  [y/n/s=skip all]
```

Type `y` to apply, `n` to skip, or `s` to skip all remaining fixes.

**Output files:**

```
.aquilax/
├── fix.md                  ← Professional markdown fix report (before/after per finding)
└── data/
    └── fix.json            ← Structured JSON with all applied fixes (incremental)
```

Fix reports are incremental — re-running `fix` on a file replaces only that file's entries; other files' fix history is preserved.

**Auto-analyze:**

If `fix` is called on a file that hasn't been analyzed yet, it automatically runs `analyze` on that file first before proceeding with fixes.

---

#### 📊 Retrieving Information

##### Pull Scan Results
Fetch detailed results from a completed scan:

```bash
aquilax pull <scan_id> [options]
```

**Options:**
| Option | Description | Default |
|--------|-------------|---------|
| `--org-id` | Organization ID | From config |
| `--group-id` | Group ID | From config |
| `--format` | Output format (`json` or `table`) | `table` |

**Example:**
```bash
aquilax pull 507f1f77bcf86cd799439013 --format table
```

##### Get Organizations
List all organizations accessible to your account:

```bash
aquilax get orgs
```

**Output:**
```
Organizations List:
+-------------------+---------------------------+
| Organization Name | Organization ID           |
+===================+===========================+
| My Company        | 507f1f77bcf86cd799439011 |
| Test Org          | 507f1f77bcf86cd799439014 |
+-------------------+---------------------------+
```

##### Get Groups
List all groups within an organization:

```bash
aquilax get groups [--org-id <org_id>]
```

If `--org-id` is not provided, uses the default organization from your configuration.

##### Get Scan Details
Retrieve comprehensive details about a specific scan:

```bash
aquilax get scan-details --scan-id <scan_id> [options]
```

**Options:**
| Option | Description | Default |
|--------|-------------|---------|
| `--org-id` | Organization ID | From config |
| `--group-id` | Group ID | From config |
| `--format` | Output format (`json` or `table`) | `table` |

**Example:**
```bash
aquilax get scan-details --scan-id 507f1f77bcf86cd799439013
```

---

### 🎨 Output Formats

#### Table Format (Default)
Beautiful, color-coded console output:

```
╭─────────────────┬──────────────────────┬─────────────────────────┬──────────┬─────────┬────────╮
│ Scanner         │ Path                 │ Vulnerability           │ Severity │ CWE     │ OWASP  │
├─────────────────┼──────────────────────┼─────────────────────────┼──────────┼─────────┼────────┤
│ secret_scanner  │ config/database.yml  │ Hardcoded API Key       │ HIGH     │ CWE-798 │ A02    │
│ sast_scanner    │ app/controllers/...  │ SQL Injection           │ CRITICAL │ CWE-89  │ A03    │
│ sca_scanner     │ package.json         │ Vulnerable Dependency   │ MEDIUM   │ CWE-937 │ A06    │
╰─────────────────┴──────────────────────┴─────────────────────────┴──────────┴─────────┴────────╯
```

#### JSON Format
Machine-readable output for automation and integration:

```bash
aquilax scan https://github.com/myorg/myrepo --format json
```

```json
{
  "scan_id": "507f1f77bcf86cd799439013",
  "status": "COMPLETED",
  "findings": [
    {
      "scanner": "secret_scanner",
      "path": "config/database.yml",
      "vuln": "Hardcoded API Key",
      "severity": "HIGH",
      "cwe": ["CWE-798"],
      "owasp": ["A02"]
    }
  ]
}
```

---

### 🔒 Security Policy Thresholds

AquilaX CLI enforces security policies configured at the group level in your AquilaX platform. Scans will fail if vulnerabilities exceed defined thresholds.

**Threshold Categories:**
- **Total** - Maximum total number of vulnerabilities
- **CRITICAL** - Maximum critical severity findings
- **HIGH** - Maximum high severity findings
- **MEDIUM** - Maximum medium severity findings
- **LOW** - Maximum low severity findings

**Example Policy:**
```
Security Policy Thresholds:
  - total: 10
  - CRITICAL: 0
  - HIGH: 2
  - MEDIUM: 5
  - LOW: 10
```

If thresholds are exceeded:
```
Thresholds exceeded: CRITICAL (2) > 0; HIGH (5) > 2
Pipeline failed due to security policy violations.
```

---

## 🔧 Advanced Usage

### Environment Variables

You can configure AquilaX CLI using environment variables:

```bash
export AQUILAX_SERVER="https://your-instance.com"
```

### Configuration File

Authentication and defaults are stored at:
- **Linux/Mac:** `~/.aquilax/config.json`
- **Windows:** `%USERPROFILE%\.aquilax\config.json`

Example configuration:
```json
{
  "apiToken": "your_api_token",
  "baseUrl": "https://aquilax.ai",
  "org_id": "507f1f77bcf86cd799439011",
  "group_id": "507f1f77bcf86cd799439012"
}
```

---

## 🎓 Use Cases

### Developer Workflows

**Pre-Commit Security Checks:**
```bash
# Add to .git/hooks/pre-commit
aquilax scan $(git config --get remote.origin.url) --branch $(git branch --show-current)
```

### CI/CD Integration

**Jenkins Pipeline:**
```groovy
stage('Security Scan') {
    steps {
        sh 'pip install aquilax'
        sh 'aquilax login ${AQUILAX_TOKEN}'
        sh 'aquilax ci-scan ${GIT_URL} --fail-on-vulns --format json > scan-results.json'
    }
}
```

**Azure DevOps:**
```yaml
- task: CmdLine@2
  inputs:
    script: |
      pip install aquilax
      aquilax login $(AQUILAX_TOKEN)
      aquilax ci-scan $(Build.Repository.Uri) --fail-on-vulns
```

### Security Team Automation

**Scheduled Scans:**
```bash
#!/bin/bash
# Scan all repositories in your organization
for repo in $(cat repos.txt); do
  aquilax scan $repo --sync --format json > "scans/$(basename $repo).json"
done
```

---

## 🛠️ Troubleshooting

### Common Issues

#### Module Import Errors
**Problem:** `ModuleNotFoundError: No module named 'aquilax'`

**Solution:** Ensure the package is installed and your virtual environment is activated:
```bash
pip install aquilax
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows
```

#### Unauthorized Error
**Problem:** `401 Unauthorized` when running commands

**Solution:** Verify your API token is correct and has necessary permissions:
```bash
aquilax logout
aquilax login YOUR_CORRECT_TOKEN
```

#### Scan Failures
**Problem:** Scan fails with "Repository not accessible"

**Solution:** 
- Ensure the Git repository URL is correct and accessible
- For private repositories, ensure your AquilaX platform has appropriate access credentials
- Verify the branch name exists: `--branch your-branch-name`

#### Threshold Errors
**Problem:** `Thresholds exceeded` errors

**Solution:** 
- Review your group's security policy settings in the AquilaX web dashboard
- Adjust thresholds if they're too strict, or fix the vulnerabilities
- Use `--format json` to get detailed findings for remediation

#### Connection Issues
**Problem:** Cannot connect to AquilaX server

**Solution:**
```bash
# For on-premise installations, verify server URL
aquilax login YOUR_TOKEN --server https://your-correct-url.com

# Check if server is accessible
curl https://your-aquilax-server.com/health
```

---

## 🤝 Contributing

We welcome contributions to AquilaX CLI! Here's how you can help:

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Commit** your changes (`git commit -m 'Add amazing feature'`)
4. **Push** to the branch (`git push origin feature/amazing-feature`)
5. **Open** a Pull Request

### Development Setup

```bash
git clone https://github.com/AquilaX-AI/AquilaX-Client.git
cd AquilaX-Client
pip install -e .
```

---

## 📄 License

This project is licensed under the **Apache License 2.0**. See the [LICENSE](LICENSE) file for details.

---

## 🆘 Support

Need help? We're here for you!

- 📧 **Email:** [support@aquilax.ai](mailto:support@aquilax.ai)
- 🌐 **Website:** [https://aquilax.ai](https://aquilax.ai)
- 📖 **Documentation:** [https://docs.aquilax.ai](https://docs.aquilax.ai)
- 🐛 **Issues:** [GitHub Issues](https://github.com/AquilaX-AI/AquilaX-Client/issues)

---

## 🗺️ What's Coming Next

- [x] **SARIF Export** - Export CI/CD scan results in SARIF format
- [x] **Local Code Analysis** - Scan local files and directories with AI-powered detection
- [x] **Incremental Reports** - Persistent, cumulative security reports with per-file merge
- [x] **AI-Powered Fix** - Automatically fix vulnerabilities with `aquilax fix`
- [ ] **IDE Plugins** - Use AquilaX directly in VS Code and IntelliJ
- [ ] **Instant Notifications** - Get alerts via Slack, Teams, or email
- [ ] **Advanced Filters** - Filter results by severity, type, or file

---

## 🌟 Why Choose AquilaX CLI?

✅ **Complete Security Coverage** - Multiple specialized scanners in one tool
✅ **Local + Remote** - Scan local files/directories or remote Git repositories
✅ **AI-Powered Analysis** - Instant, intelligent findings with remediation guidance
✅ **AI-Powered Fix** - Automatically fix vulnerabilities with a single command
✅ **Incremental Reports** - Persistent reports that merge across scan runs
✅ **Fast & Efficient** - Quick scans without slowing down your workflow
✅ **Automation Ready** - Perfect for CI/CD pipelines
✅ **Easy to Use** - Clean, color-coded terminal output and professional markdown reports
✅ **Enterprise Trusted** - Used by security teams worldwide

---

<div align="center">

**Made with ❤️ by the AquilaX Team**

[⬆ Back to Top](#️-aquilax)

</div>