# Automated Web Security Scanner Using Python

A beginner-friendly, defensive tool that checks common HTTP security headers and exports JSON/CSV reports.

## Features
- Checks HTTPS usage and six common security headers.
- Explains each check and gives recommendations for missing headers.
- Exports JSON and CSV reports.
- Uses request timeouts, disables automatic redirects, and rejects hostnames that resolve to non-public IP addresses.
- Read-only: it does not exploit vulnerabilities or attempt authentication.

## Requirements
- Python 3.10 or newer recommended
- Internet access for installing the dependency and scanning a permitted public target

## Setup (Windows / VS Code terminal)
1. Extract the ZIP file.
2. Open the extracted `web_security_scanner_project` folder in VS Code.
3. Open Terminal → New Terminal.
4. Create a virtual environment:
   ```powershell
   py -m venv .venv
   ```
5. Activate it:
   ```powershell
   .\.venv\Scripts\Activate.ps1
   ```
   If PowerShell blocks activation, use Command Prompt terminal and run:
   ```bat
   .venv\Scripts\activate.bat
   ```
6. Install dependencies:
   ```powershell
   python -m pip install -r requirements.txt
   ```
7. Run against a website you own or have permission to assess:
   ```powershell
   python scanner.py https://example.com
   ```
8. Optional: set a timeout and output names:
   ```powershell
   python scanner.py https://example.com --timeout 8 --out reports/my_scan.json --csv reports/my_scan.csv
   ```

## macOS / Linux
```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python scanner.py https://example.com
```

## Output
- `reports/scan_report.json`: detailed machine-readable report
- `reports/scan_report.csv`: spreadsheet-friendly findings
- Terminal output: summary, score, present/missing checks, and recommendations

The score is a simple educational configuration indicator, not a standardized security rating. A header being present does not prove it is correctly configured. Some headers may not apply to every application.

## Safety and limitations
- Scan only systems you own or have explicit permission to assess.
- This tool checks headers only; it does not test for SQL injection, XSS, authentication issues, or other application vulnerabilities.
- Redirects are not followed. If the target redirects, review the destination and scan it separately if authorized.
- The public-IP validation is a basic safety measure, not a substitute for a hardened security testing environment.
- This project has not been represented as independently audited or penetration-tested.

## Suggested demonstration
1. Run `python scanner.py https://example.com`.
2. Show the terminal findings.
3. Open the generated JSON and CSV files.
4. Explain one missing header and its recommended mitigation.

## Project author
Add your name, course, college, and submission date before submitting.
