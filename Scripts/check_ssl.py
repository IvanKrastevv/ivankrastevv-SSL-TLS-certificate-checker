#!/usr/bin/env python3
"""
check_ssl.py
Checks SSL/TLS certificate expiry for hosts listed in sites.txt (or overridden by env/config).
Outputs human-readable table and optionally sends alerts (Slack) on thresholds.

Usage:
Environment variables (optional):
  SITES_FILE = os.environ.get("SITES_FILE", "sites.txt")
  WARN_DAYS  - days threshold for warning (default: 30)
  CRIT_DAYS  - days threshold for critical (default: 7)
  SLACK_WEBHOOK - optional Slack webhook URL to send alerts
  PARALLEL_WORKERS - number of concurrent workers (default: 16)

Legend:
 read_sites(path): read host list from file
 parse_host_port(line): split host and optional port
 get_cert_expiry(host, port, timeout): connect via TLS and return (expiry_utc, subject, issuer) (robust parsing with cryptography fallback)
 human_subject(subject): normalize subject to dict for printing
 format_line(hostline, result): helper to format one-line result
 maybe_alert_alerts(results): send Slack webhook summary if configured
 check_all(sites): run checks concurrently and collect results
 print_summary(results): print human-readable summary to stdout
 main(): orchestrates the workflow and sets exit code
 
"""

# === Standard library imports ===
import socket       # For TCP network connections
import ssl          # For TLS/SSL handshake and certificate retrieval
from datetime import datetime, timezone  # For expiry date comparison
from concurrent.futures import ThreadPoolExecutor, as_completed  # For parallel checks
import os           # For environment variable access
import sys          # For exiting with codes
import json         # For Slack payload encoding
import urllib.request, urllib.error  # For sending webhook messages
import traceback    # For debug printing of full exceptions

# === Third-party import ===
# cryptography is used for robust parsing of certificates in binary (DER) form
from cryptography import x509
from cryptography.hazmat.backends import default_backend

# === Configuration constants (can be overridden via environment variables) ===
SITES_FILE = os.environ.get("SITES_FILE", "sites.txt")
WARN_DAYS = int(os.environ.get("WARN_DAYS", "30"))
CRIT_DAYS = int(os.environ.get("CRIT_DAYS", "7"))
SLACK_WEBHOOK = os.environ.get("SLACK_WEBHOOK", "").strip()
PARALLEL = int(os.environ.get("PARALLEL_WORKERS", "16"))
CONNECT_TIMEOUT = float(os.environ.get("CONNECT_TIMEOUT", "6.0"))

# -----------------------------------------------------------------------------
# Utility function: Read sites file and return list of hostnames
# -----------------------------------------------------------------------------
def read_sites(file_path):
    """
    Reads site list from a text file, ignoring comments and blank lines.
    Returns a list of host strings (e.g., ["example.com", "google.com:443"]).
    """
    try:
        with open(file_path, "r") as f:
            # Strip whitespace and ignore empty/commented lines
            lines = [ln.strip() for ln in f if ln.strip() and not ln.strip().startswith("#")]
        return lines
    except FileNotFoundError:
        print(f"[ERROR] Sites file not found: {file_path}")
        return []

# -----------------------------------------------------------------------------
# Utility: Parse "host:port" strings into (host, port)
# -----------------------------------------------------------------------------
def parse_host_port(hostline):
    """
    Splits a string like 'example.com:8443' into ('example.com', 8443).
    Defaults to port 443 if not specified.
    """
    if ":" in hostline:
        parts = hostline.rsplit(":", 1)  # Split only on last colon
        host = parts[0]
        try:
            port = int(parts[1])
        except ValueError:
            port = 443
    else:
        host = hostline
        port = 443
    return host, port

# -----------------------------------------------------------------------------
# Core function: Retrieve and parse the SSL certificate for a given host
# -----------------------------------------------------------------------------
def get_cert_expiry(host, port=443, timeout=5):
    """
    Connects to a host:port over TLS, retrieves the certificate,
    and returns (expiry_datetime_utc, subject, issuer).
    Works across Python versions (3.9–3.13) and platforms.
    """

    # Create an SSL context but disable verification so we can retrieve even expired or self-signed certificates.
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    # Create TCP connection with timeout, then wrap in SSL
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=host) as ssock:
            # Try to get parsed cert info (dict form)
            cert = ssock.getpeercert()
            not_after = cert.get("notAfter") if cert else None

            # If missing, fallback to DER binary parse using cryptography
            if not not_after:
                der_cert = ssock.getpeercert(binary_form=True)
                if not der_cert:
                    raise ValueError("Could not retrieve certificate in binary form")

                # Parse DER cert into X.509 object
                x509_cert = x509.load_der_x509_certificate(der_cert, default_backend())
                expiry = x509_cert.not_valid_after_utc
                subject = x509_cert.subject.rfc4514_string()
                issuer = x509_cert.issuer.rfc4514_string()
                return expiry, subject, issuer

            # Parse textual notAfter format, example: "Jun 12 12:00:00 2026 GMT"
            try:
                expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            except Exception:
                expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y")
            expiry = expiry.replace(tzinfo=timezone.utc)

            # Subject and issuer come as tuple-of-tuples
            subject = cert.get("subject", ())
            issuer = cert.get("issuer", ())
            return expiry, subject, issuer

# -----------------------------------------------------------------------------
# Helper: Convert subject data to a readable dict
# -----------------------------------------------------------------------------
def human_subject(subject):
    """
    Converts subject info into dict form for easy CN extraction.
    Handles both string (RFC4514) and tuple formats.
    """
    if isinstance(subject, str):
        # e.g. "CN=example.com,O=Company,L=City"
        d = {}
        for part in subject.split(","):
            if "=" in part:
                k, v = part.strip().split("=", 1)
                d[k] = v
        return d
    elif isinstance(subject, (tuple, list)):
        # e.g. ((('commonName', 'example.com'),),)
        d = {}
        for item in subject:
            for (k, v) in item:
                d[k] = v
        return d
    else:
        return {}

# -----------------------------------------------------------------------------
# Helper: Send Slack alert if any WARNING or CRITICAL sites found
# -----------------------------------------------------------------------------
def maybe_alert_alerts(results):
    """
    If SLACK_WEBHOOK is set, sends one summary message listing
    all CRITICAL and WARNING items.
    """
    if not SLACK_WEBHOOK:
        return  # Skip if no webhook configured

    criticals = []
    warnings = []

    for host, res in results.items():
        # If host failed entirely, mark as critical
        if isinstance(res, Exception):
            criticals.append(f"{host} - ERROR - {res}")
            continue

        expiry_dt, subject, issuer = res
        days_left = (expiry_dt - datetime.now(timezone.utc)).days

        # Classify based on remaining days
        if days_left < 0:
            criticals.append(f"{host} - EXPIRED {expiry_dt.date()} ({days_left} days)")
        elif days_left <= CRIT_DAYS:
            criticals.append(f"{host} - CRITICAL {expiry_dt.date()} ({days_left} days)")
        elif days_left <= WARN_DAYS:
            warnings.append(f"{host} - WARNING {expiry_dt.date()} ({days_left} days)")

    if not criticals and not warnings:
        print("[INFO] No alerts to send.")
        return

    # Build Slack message text (basic markdown-style)
    text_lines = []
    if criticals:
        text_lines.append("*CRITICAL*:")
        text_lines.extend(f"• {c}" for c in criticals)
    if warnings:
        text_lines.append("*Warnings*:")
        text_lines.extend(f"• {w}" for w in warnings)

    payload = json.dumps({"text": "\n".join(text_lines)}).encode("utf-8")

    # POST to Slack webhook
    try:
        req = urllib.request.Request(
            SLACK_WEBHOOK,
            data=payload,
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            status = resp.getcode()
            print(f"[ALERT] Slack webhook response: {status}")
    except Exception as e:
        print(f"[ALERT ERROR] Failed to send Slack webhook: {e}")

# -----------------------------------------------------------------------------
# Parallel checker: runs get_cert_expiry() on multiple sites concurrently
# -----------------------------------------------------------------------------
def check_all(sites):
    """
    Runs SSL expiry checks in parallel using a ThreadPoolExecutor.
    Returns dict: {site: (expiry, subject, issuer) or Exception}.
    """
    results = {}
    if not sites:
        print("[WARN] No sites to check.")
        return results

    # Limit worker threads to avoid resource exhaustion
    with ThreadPoolExecutor(max_workers=min(PARALLEL, max(2, len(sites)))) as ex:
        futures = {}
        for site in sites:
            host, port = parse_host_port(site)
            # Submit each host check as a separate thread
            futures[ex.submit(get_cert_expiry, host, port)] = site

        # Iterate futures as they complete
        for fut in as_completed(futures):
            site = futures[fut]
            try:
                res = fut.result()  # May raise if check failed
                results[site] = res
            except Exception as e:
                # Catch errors per host so script continues
                print(f"[DEBUG] Exception for {site}: {traceback.format_exc()}")
                results[site] = e

    return results

# -----------------------------------------------------------------------------
# Output summary: print status lines for all sites
# -----------------------------------------------------------------------------
def print_summary(results):
    """
    Prints a formatted summary of all SSL expiry checks.
    """
    print("----- SSL Certificate Expiry Summary -----")
    for site, res in results.items():
        if isinstance(res, Exception):
            # Print error message
            print(f"{site} - ERROR: {res}")
        else:
            expiry, subject, issuer = res
            days = (expiry - datetime.now(timezone.utc)).days

            # Determine severity based on thresholds
            if days < 0:
                status = "EXPIRED"
            elif days <= CRIT_DAYS:
                status = "CRITICAL"
            elif days <= WARN_DAYS:
                status = "WARNING"
            else:
                status = "OK"

            subj = human_subject(subject)
            cn = subj.get("commonName") or subj.get("CN") or ""
            print(f"{site} | CN={cn} | Expires={expiry.strftime('%Y-%m-%d %H:%M:%S %Z')} | DaysLeft={days} | {status}")
    print("------------------------------------------")

# -----------------------------------------------------------------------------
# Main entry point
# -----------------------------------------------------------------------------
def main():
    """
    Reads site list, runs checks, prints summary,
    optionally sends Slack alerts, and sets exit code.
    """
    sites = read_sites(SITES_FILE)
    if not sites:
        sys.exit(1)  # Exit early if no sites configured

    results = check_all(sites)
    print_summary(results)
    maybe_alert_alerts(results)

    # Compute overall exit code based on severities
    exit_code = 0
    for res in results.values():
        if isinstance(res, Exception):
            exit_code = max(exit_code, 2)
            continue
        expiry = res[0]
        days = (expiry - datetime.now(timezone.utc)).days
        if days < 0 or days <= CRIT_DAYS:
            exit_code = max(exit_code, 2)
        elif days <= WARN_DAYS:
            exit_code = max(exit_code, 1)

    sys.exit(exit_code)

# -----------------------------------------------------------------------------
# Run main if script is executed directly
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    main()
