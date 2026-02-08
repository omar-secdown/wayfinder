#!/usr/bin/env python3
"""
SecurityTrails IP/CIDR Enumeration Module
Fetches all associated IP ranges (CIDRs) for a target company/domain
"""

import requests
import time
import sys
import ipaddress

import config
from logger import logger


def get_securitytrails_cidrs(company_domain, api_key=None, page_size=100):
    """
    Fetch all associated CIDRs for a company from SecurityTrails.

    Args:
        company_domain: Target company domain (e.g., "cat.com")
        api_key: SecurityTrails API key (reads from config if not provided)
        page_size: Number of results per page (default: 100)

    Returns:
        List of CIDR strings: ['192.168.1.0/24', '10.0.0.0/8', ...]
    """
    if not api_key:
        api_key = config.API_KEYS.get('SECURITYTRAILS_API_KEY')

    if not api_key:
        logger.error("SecurityTrails API key not found! Configure it in .env")
        return []

    headers = {
        "APIKEY": api_key,
        "accept": "application/json"
    }

    base_url = "https://api.securitytrails.com/v2"
    all_cidrs = []
    page = 1

    print(f"[*] Fetching CIDRs for: {company_domain}")
    print(f"{'='*60}")

    while True:
        try:
            url = f"{base_url}/company/{company_domain}/associated-ips"
            params = {
                "page": page,
                "page_size": page_size
            }

            print(f"[*] Fetching page {page}...", end=" ", flush=True)

            response = requests.get(url, headers=headers, params=params, timeout=30)

            if response.status_code == 429:
                print("Rate limited!")
                retry_after = int(response.headers.get('Retry-After', 60))
                logger.warning("Waiting %d seconds...", retry_after)
                time.sleep(retry_after)
                continue

            if response.status_code != 200:
                print(f"Error {response.status_code}")
                if response.status_code == 404:
                    logger.warning("Domain '%s' not found in SecurityTrails database", company_domain)
                else:
                    logger.warning("Response: %s", response.text)
                break

            data = response.json()
            records = data.get('records', [])

            if not records:
                print("No more records!")
                break

            page_cidrs = []
            for record in records:
                cidr = record.get('cidr')
                if cidr:
                    page_cidrs.append(cidr)

            all_cidrs.extend(page_cidrs)
            print(f"Found {len(page_cidrs)} CIDRs (Total: {len(all_cidrs)})")

            record_count = data.get('record_count', 0)
            current_total = page * page_size

            if current_total >= record_count or len(records) < page_size:
                print("[+] Reached last page!")
                break

            page += 1
            time.sleep(1.2)

        except requests.exceptions.Timeout:
            print("Timeout!")
            logger.warning("Retrying page %d...", page)
            time.sleep(2)
            continue

        except Exception as e:
            logger.error("Error: %s", e)
            break

    print(f"{'='*60}")
    print(f"[+] Total CIDRs collected: {len(all_cidrs)}")

    return all_cidrs


def expand_cidrs_to_ips(cidrs, max_ips_per_cidr=10000):
    """
    Expand CIDR ranges to individual IPs.
    WARNING: Use carefully with large ranges!

    Args:
        cidrs: List of CIDR strings
        max_ips_per_cidr: Skip CIDRs larger than this (default: 10000)

    Returns:
        Set of individual IP addresses
    """
    all_ips = set()
    skipped = []

    logger.info("Expanding %d CIDRs to individual IPs...", len(cidrs))
    logger.info("Skipping networks larger than %d IPs", max_ips_per_cidr)

    for cidr in cidrs:
        try:
            network = ipaddress.ip_network(cidr, strict=False)

            if network.num_addresses > max_ips_per_cidr:
                skipped.append(f"{cidr} ({network.num_addresses} IPs)")
                continue

            for ip in network.hosts():
                all_ips.add(str(ip))

        except Exception as e:
            logger.warning("Error expanding %s: %s", cidr, e)
            continue

    if skipped:
        logger.warning("Skipped %d large networks:", len(skipped))
        for skip_info in skipped[:10]:
            logger.warning("    - %s", skip_info)
        if len(skipped) > 10:
            logger.warning("    ... and %d more", len(skipped) - 10)

    logger.info("Expanded to %d individual IPs", len(all_ips))

    return all_ips


def save_cidrs_to_file(cidrs, output_file):
    """
    Save CIDRs to file (one per line).

    Args:
        cidrs: List of CIDR strings
        output_file: Path to output file
    """
    with open(output_file, 'w') as f:
        for cidr in cidrs:
            f.write(f"{cidr}\n")

    logger.info("CIDRs saved to: %s", output_file)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 securitytrails_ips.py <company_domain>")
        print("Example: python3 securitytrails_ips.py cat.com")
        sys.exit(1)

    domain = sys.argv[1]

    print(f"[*] Starting IP enumeration for: {domain}")
    print(f"{'='*60}\n")

    cidrs = get_securitytrails_cidrs(domain)

    if cidrs:
        ips = expand_cidrs_to_ips(cidrs, max_ips_per_cidr=10000)

        if ips:
            ips_file = f"{domain}_ips.txt"
            with open(ips_file, 'w') as f:
                for ip in sorted(ips):
                    f.write(f"{ip}\n")

            print(f"\n[+] {len(ips)} IPs saved to: {ips_file}")
        else:
            print(f"\n[!] No IPs extracted (all CIDRs were too large)")
    else:
        print("\n[-] No CIDRs found")
