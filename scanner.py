#!/usr/bin/env python3
"""
Automated Web Security Scanner
Educational, read-only checks for common HTTP security headers.

Use only on websites you own or are authorized to assess.
This tool is not a full vulnerability scanner and does not prove a site is secure.
"""
import argparse
import csv
import ipaddress
import json
import socket
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import requests

CHECKS = {
    "Content-Security-Policy": {
        "purpose": "Helps control which sources a browser may load content from.",
        "recommendation": "Design and deploy a CSP suited to the application; test in report-only mode first."
    },
    "Strict-Transport-Security": {
        "purpose": "Tells browsers to use HTTPS for future visits.",
        "recommendation": "Enable HSTS only after HTTPS works correctly across the intended domain."
    },
    "X-Content-Type-Options": {
        "purpose": "Helps prevent MIME-type sniffing.",
        "recommendation": "Set X-Content-Type-Options: nosniff."
    },
    "X-Frame-Options": {
        "purpose": "Helps reduce clickjacking risk in browsers that support it.",
        "recommendation": "Set X-Frame-Options: DENY or SAMEORIGIN, or use CSP frame-ancestors."
    },
    "Referrer-Policy": {
        "purpose": "Controls how much referrer information browsers send.",
        "recommendation": "Choose a policy such as strict-origin-when-cross-origin based on application needs."
    },
    "Permissions-Policy": {
        "purpose": "Lets a site restrict use of selected browser features.",
        "recommendation": "Define a Permissions-Policy appropriate to the features the site uses."
    },
}

USER_AGENT = "EducationalWebSecurityScanner/1.0"


def validate_public_hostname(hostname):
    """Reject localhost and hostnames resolving to non-public IP addresses."""
    if not hostname:
        raise ValueError("URL must include a hostname.")
    if hostname.lower() in {"localhost", "localhost.localdomain"} or hostname.endswith(".local"):
        raise ValueError("Local hostnames are not allowed by this educational scanner.")
    try:
        addresses = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError(f"Could not resolve hostname: {exc}") from exc
    if not addresses:
        raise ValueError("Hostname did not resolve to an IP address.")
    for entry in addresses:
        ip = ipaddress.ip_address(entry[4][0].split("%")[0])
        if not ip.is_global:
            raise ValueError("Target resolves to a non-public IP address; scan cancelled.")
    return True


def normalize_url(raw_url):
    raw_url = raw_url.strip()
    if "://" not in raw_url:
        raw_url = "https://" + raw_url
    parsed = urlparse(raw_url)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("Only http:// and https:// URLs are supported.")
    if parsed.username or parsed.password:
        raise ValueError("Do not include usernames or passwords in the URL.")
    if not parsed.hostname:
        raise ValueError("Please enter a valid URL, for example https://example.com")
    if parsed.port and not (1 <= parsed.port <= 65535):
        raise ValueError("Invalid port.")
    validate_public_hostname(parsed.hostname)
    return raw_url, parsed


def scan_url(raw_url, timeout=8):
    url, parsed = normalize_url(raw_url)
    result = {
        "target": url,
        "scan_time_utc": datetime.now(timezone.utc).isoformat(),
        "status": "ERROR",
        "http_status": None,
        "https_used": parsed.scheme == "https",
        "security_score": 0,
        "score_max": len(CHECKS) + 1,
        "checks": [],
        "notes": [
            "Read-only header check only; not a comprehensive vulnerability assessment.",
            "Redirects are not followed. Scan the final HTTPS URL separately if appropriate."
        ],
    }
    try:
        response = requests.get(
            url,
            timeout=timeout,
            allow_redirects=False,
            headers={"User-Agent": USER_AGENT},
            stream=True,
        )
        result["http_status"] = response.status_code
        headers = response.headers
        response.close()
        result["status"] = "COMPLETED"
        if parsed.scheme == "https":
            result["security_score"] += 1
        result["checks"].append({
            "name": "HTTPS",
            "present": parsed.scheme == "https",
            "purpose": "Encrypts traffic between the browser and website when configured correctly.",
            "recommendation": "Use HTTPS and redirect HTTP to HTTPS after verifying the site configuration."
        })
        for header, details in CHECKS.items():
            present = header in headers and bool(headers.get(header, "").strip())
            if present:
                result["security_score"] += 1
            result["checks"].append({
                "name": header,
                "present": present,
                "observed_value": headers.get(header, "") if present else None,
                "purpose": details["purpose"],
                "recommendation": details["recommendation"],
            })
        if 300 <= response.status_code < 400:
            result["notes"].append(
                "The server returned a redirect. Redirects are intentionally not followed; scan the destination URL separately."
            )
    except requests.exceptions.SSLError:
        result["status"] = "ERROR"
        result["error"] = "TLS/SSL verification failed. Check the certificate and URL."
    except requests.exceptions.Timeout:
        result["status"] = "ERROR"
        result["error"] = f"Request timed out after {timeout} seconds."
    except requests.exceptions.RequestException as exc:
        result["status"] = "ERROR"
        result["error"] = f"Request failed: {exc}"
    except ValueError as exc:
        result["status"] = "ERROR"
        result["error"] = str(exc)
    return result


def save_json(result, path):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as file:
        json.dump(result, file, indent=2, ensure_ascii=False)


def save_csv(result, path):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(
            file,
            fieldnames=["target", "scan_time_utc", "http_status", "check", "present", "purpose", "recommendation", "observed_value"]
        )
        writer.writeheader()
        for check in result.get("checks", []):
            writer.writerow({
                "target": result.get("target"),
                "scan_time_utc": result.get("scan_time_utc"),
                "http_status": result.get("http_status"),
                "check": check.get("name"),
                "present": check.get("present"),
                "purpose": check.get("purpose"),
                "recommendation": check.get("recommendation"),
                "observed_value": check.get("observed_value", ""),
            })


def print_report(result):
    print("\n=== AUTOMATED WEB SECURITY SCANNER ===")
    print(f"Target: {result.get('target')}")
    print(f"Status: {result.get('status')}")
    print(f"HTTP status: {result.get('http_status')}")
    if result.get("error"):
        print(f"Error: {result['error']}")
    if result.get("status") == "COMPLETED":
        score = result["security_score"]
        maximum = result["score_max"]
        print(f"Configuration score: {score}/{maximum} ({score / maximum * 100:.0f}%)")
        print("\nFindings:")
        for check in result["checks"]:
            state = "PRESENT" if check["present"] else "MISSING"
            print(f"- [{state}] {check['name']}: {check['purpose']}")
            if not check["present"]:
                print(f"  Recommendation: {check['recommendation']}")
    for note in result.get("notes", []):
        print(f"Note: {note}")


def main():
    parser = argparse.ArgumentParser(description="Read-only website security-header checker.")
    parser.add_argument("url", help="Target URL, e.g. https://example.com")
    parser.add_argument("--timeout", type=int, default=8, help="Request timeout in seconds (default: 8)")
    parser.add_argument("--out", default="reports/scan_report.json", help="JSON output path")
    parser.add_argument("--csv", default="reports/scan_report.csv", help="CSV output path")
    args = parser.parse_args()

    if args.timeout < 1 or args.timeout > 30:
        print("Timeout must be between 1 and 30 seconds.", file=sys.stderr)
        sys.exit(2)

    result = scan_url(args.url, timeout=args.timeout)
    print_report(result)
    save_json(result, args.out)
    save_csv(result, args.csv)
    print(f"\nJSON report saved to: {args.out}")
    print(f"CSV report saved to:  {args.csv}")
    if result.get("status") != "COMPLETED":
        sys.exit(1)


if __name__ == "__main__":
    main()
