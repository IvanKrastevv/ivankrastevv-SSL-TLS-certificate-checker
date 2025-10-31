#!/usr/bin/env python3
"""
check_ssl.py
Checks SSL/TLS certificate expiry for hosts listed in sites.txt (or overridden by env/config).
Outputs human-readable table and optionally sends alerts (Slack/Teams/Email) on thresholds.

Usage:
  python3 check_ssl.py
Environment variables (optional):
  SITES_FILE - path to sites file (default: ./sites.txt)
  WARN_DAYS  - days threshold for warning (default: 30)
  CRIT_DAYS  - days threshold for critical (default: 7)
  SLACK_WEBHOOK - optional Slack webhook URL to send alerts
  TEAMS_WEBHOOK - optional Slack webhook URL to send alerts
  PARALLEL_WORKERS - number of concurrent workers (default: 16)
"""

import socket
import ssl
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
import os
import sys
import json
import urllib.request
import urllib.error
import traceback

SITES_FILE = os.environ.get("SITES_FILE", "sites.txt")
WARN_DAYS = int(os.environ.get("WARN_DAYS", "30"))
CRIT_DAYS = int(os.environ.get("CRIT_DAYS", "7"))
SLACK_WEBHOOK = os.environ.get("SLACK_WEBHOOK", "").strip()
TEAMS_WEBHOOK = os.environ.get("SLACK_WEBHOOK", "").strip()
PARALLEL = int(os.environ.get("PARALLEL_WORKERS", "16"))
CONNECT_TIMEOUT = float(os.environ.get("CONNECT_TIMEOUT", "6.0"))

def read_sites(file_path):
    try:
        with open(file_path, "r") as f:
            lines = [ln.strip() for ln in f if ln.strip() and not ln.strip().startswith("#")]
        return lines
    except FileNotFoundError:
        print(f"[ERROR] File containing URLs not found: {file_path}")
        return []


def parse_host_port(hostline):
    # Accept hostname or host:port
    if ":" in hostline:
        parts = hostline.rsplit(":", 1)
        host = parts[0]
        try:
            port = int(parts[1])
        except ValueError:
            port = 443
    else:
        host = hostline
        port = 443
    return host, port

  
def get_cert_expiry(host, port=443, timeout=CONNECT_TIMEOUT):
    """
    Returns a tuple: (expiry_datetime_utc, subject_dict, issuer_dict)
    Or raises an exception on failure.
    """
    context = ssl.create_default_context()
    # do not verify to ensure we can fetch even if chain is problematic - still returns cert
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    with socket.create_connection((host, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=host) as ssock:
            cert = ssock.getpeercert()
            # getpeercert returns a dict; 'notAfter' like 'Jun 10 12:00:00 2026 GMT'
            not_after = cert.get('notAfter')
            if not not_after:
                raise ValueError("Certificate missing 'notAfter'")
            try:
                expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            except Exception:
                # fallback without timezone parse (robustness)
                expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y")
            # treat as UTC/GMT
            expiry = expiry.replace(tzinfo=timezone.utc)
            subject = cert.get("subject", ())
            issuer = cert.get("issuer", ())
            return expiry, subject, issuer


def human_subject(subject_tuple):
    # Convert subject tuple list to readable dict
    try:
        d = {}
        for item in subject_tuple:
            for (k, v) in item:
                d[k] = v
        return d
    except Exception:
        return {}


def format_line(hostline, result):
    if isinstance(result, Exception):
        return f"{hostline} - ERROR: {result}"
    expiry_dt, subject, issuer = result
    now = datetime.now(timezone.utc)
    days_left = (expiry_dt - now).days
    status = "OK"
    if days_left < 0:
        status = "EXPIRED"
    elif days_left <= CRIT_DAYS:
        status = "CRITICAL"
    elif days_left <= WARN_DAYS:
        status = "WARNING"
    return f"{hostline} - Expires: {expiry_dt.strftime('%Y-%m-%d %H:%M:%S %Z')} ({days_left} days) - {status}"


def sending_alerts(results):
    """
    If webhooks are set are set, sends one summary alert listing CRITICAL/WARNING items.
    Simple text payload for Slack/Teams incoming webhook (blocks not used to keep dependency-free).
    """
    if not SLACK_WEBHOOK:
        return

    criticals = []
    warnings = []
    for host, res in results.items():
        if isinstance(res, Exception):
            criticals.append(f"{host} - ERROR - {res}")
            continue
        expiry_dt, subject, issuer = res
        days_left = (expiry_dt - datetime.now(timezone.utc)).days
        if days_left < 0:
            criticals.append(f"{host} - EXPIRED {expiry_dt.date()} ({days_left} days)")
        elif days_left <= CRIT_DAYS:
            criticals.append(f"{host} - CRITICAL {expiry_dt.date()} ({days_left} days)")
        elif days_left <= WARN_DAYS:
            warnings.append(f"{host} - WARNING {expiry_dt.date()} ({days_left} days)")

    if not criticals and not warnings:
        print("[INFO] No alerts to send.")
        return

    text_lines = []
    if criticals:
        text_lines.append("*CRITICAL*:")
        text_lines.extend(f"• {c}" for c in criticals)
    if warnings:
        text_lines.append("*Warnings*:")
        text_lines.extend(f"• {w}" for w in warnings)

    payload = json.dumps({"text": "\n".join(text_lines)}).encode("utf-8")
    #Slack
    try:
        req = urllib.request.Request(SLACK_WEBHOOK, data=payload,
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            status = resp.getcode()
            print(f"[ALERT] Slack webhook response: {status}")
    except Exception as e:
        print(f"[ALERT ERROR] Failed to send Slack webhook: {e}")
    #Teams
    try:
        req = urllib.request.Request(TEAMS_WEBHOOK, data=payload,
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            status = resp.getcode()
            print(f"[ALERT] Teams webhook response: {status}")
    except Exception as e:
        print(f"[ALERT ERROR] Failed to send Teams webhook: {e}")


def check_all(sites):
    results = {}
    if not sites:
        print("[WARN] No sites to check.")
        return results

    with ThreadPoolExecutor(max_workers=min(PARALLEL, max(2, len(sites)))) as ex:
        futures = {}
        for site in sites:
            host, port = parse_host_port(site)
            futures[ex.submit(get_cert_expiry, host, port)] = site

        for fut in as_completed(futures):
            site = futures[fut]
            try:
                res = fut.result()
                results[site] = res
            except Exception as e:
                # include full short message but do not crash
                err_msg = e
                print(f"[DEBUG] Exception for {site}: {traceback.format_exc()}")
                results[site] = e
    return results

  
def print_summary(results):
    print("----- SSL Certificate Expiry Summary -----")
    for site, res in results.items():
        if isinstance(res, Exception):
            print(f"{site} - ERROR: {res}")
        else:
            expiry, subject, issuer = res
            days = (expiry - datetime.now(timezone.utc)).days
            status = "OK"
            if days < 0:
                status = "EXPIRED"
            elif days <= CRIT_DAYS:
                status = "CRITICAL"
            elif days <= WARN_DAYS:
                status = "WARNING"
            subj = human_subject(subject)
            cn = subj.get("commonName") or subj.get("CN") or ""
            print(f"{site} | CN={cn} | Expires={expiry.strftime('%Y-%m-%d %H:%M:%S %Z')} | DaysLeft={days} | {status}")
    print("------------------------------------------")


def main():
    sites = read_sites(SITES_FILE)
    if not sites:
        sys.exit(1)
    results = check_all(sites)
    print_summary(results)
    # optionally alert
    sending_alerts(results)
    # exit code: 2 if any critical/expired, 1 if any warning, 0 otherwise
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

if __name__ == "__main__":
    main()
