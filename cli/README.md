# cve-explorer — Linux CLI

A fast, color-rich terminal tool to look up CVEs and generate security exploitation guides.

## Installation

```bash
cd cli
npm install
chmod +x index.js

# Optional: install globally so you can run it from anywhere
npm install -g .
```

## Usage

```bash
# Full CVE report
cve-explorer CVE-2021-44228

# Show only a specific section
cve-explorer CVE-2021-44228 --section detect
cve-explorer CVE-2021-44228 --section exploit
cve-explorer CVE-2021-44228 --section mitigate
cve-explorer CVE-2021-44228 --section resources

# Raw JSON output (for piping/scripting)
cve-explorer CVE-2021-44228 --json

# Save report to a text file
cve-explorer CVE-2021-44228 --output report.txt

# Save JSON to file
cve-explorer CVE-2021-44228 --json --output cve.json

# List all supported vulnerability guide types
cve-explorer --list-types

# Disable colors (for logging)
cve-explorer CVE-2021-44228 --no-color

# Interactive mode (no args)
cve-explorer

# Show help
cve-explorer --help
```

## Supported Guide Types

| Key | Name |
|---|---|
| sqli | SQL Injection (SQLi) |
| xss | Cross-Site Scripting (XSS) |
| rce | Remote Code Execution (RCE) |
| traversal | Path / Directory Traversal |
| lfi | Local File Inclusion (LFI) |
| cmdinj | OS Command Injection |
| deser | Insecure Deserialization |
| ssrf | Server-Side Request Forgery (SSRF) |
| xxe | XML External Entity (XXE) Injection |
| idor | Insecure Direct Object Reference (IDOR) |
| redirect | Open Redirect |
| ssti | Server-Side Template Injection (SSTI) |
| jwt | JWT Vulnerabilities |
| csrf | Cross-Site Request Forgery (CSRF) |
| fileupload | Malicious File Upload |
| generic | General Vulnerability (fallback) |

## Requirements

- Node.js >= 18 (uses native `fetch` + `AbortSignal.timeout`)
- Linux / macOS terminal for full color support

## Data Sources

- **CIRCL CVE API** (primary): https://cve.circl.lu
- **NVD API v2** (fallback): https://services.nvd.nist.gov

## ⚠️ Disclaimer

This tool is for **authorized security research and educational purposes only**.  
Never test systems you do not own or have explicit written permission to test.
