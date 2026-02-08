#!/usr/bin/env python3
"""
Shodan IP Enumeration Module
Fetches IPs for a target domain using Shodan CLI (SSL certificates only)
"""

import os
import subprocess
import tempfile
import json
import gzip

from logger import logger


def get_shodan_ips(domain):
    """
    Download and extract IPs from Shodan for a target domain.
    Uses SSL certificate matching only.

    Args:
        domain: Target domain to enumerate

    Returns:
        Set of unique IP addresses
    """
    try:
        check_shodan = subprocess.run(
            ['which', 'shodan'],
            capture_output=True,
            text=True
        )

        if check_shodan.returncode != 0:
            logger.warning("Shodan CLI not found! Install it with: pip install shodan")
            return set()

        check_init = subprocess.run(
            ['shodan', 'info'],
            capture_output=True,
            text=True,
            timeout=10
        )

        if check_init.returncode != 0:
            logger.warning("Shodan not initialized! Run: shodan init YOUR_API_KEY")
            return set()

        with tempfile.TemporaryDirectory() as temp_dir:
            raw_file = os.path.join(temp_dir, f"{domain}_results.json.gz")

            shodan_query = f'ssl:"{domain}"'

            logger.info("Shodan query: %s", shodan_query)

            download_command = [
                'shodan', 'download',
                '--limit', '-1',
                raw_file,
                shodan_query
            ]

            download_result = subprocess.run(
                download_command,
                capture_output=True,
                text=True,
                timeout=300
            )

            if download_result.returncode != 0:
                error_msg = download_result.stderr.lower()

                if 'api key' in error_msg or 'please provide' in error_msg:
                    logger.warning("Shodan API key not configured")
                elif 'unresponsive' in error_msg or 'try again' in error_msg:
                    logger.warning("Shodan API temporarily unavailable")
                elif 'quota' in error_msg or 'rate' in error_msg:
                    logger.warning("Shodan rate limit/quota exceeded")
                else:
                    stderr_lines = download_result.stderr.strip().split('\n')
                    actual_errors = [line for line in stderr_lines if 'Error:' in line or 'error' in line.lower()]
                    if actual_errors:
                        logger.warning("Shodan error: %s", actual_errors[-1])

                return set()

            if not os.path.exists(raw_file) or os.path.getsize(raw_file) == 0:
                logger.debug("No Shodan results found for %s", domain)
                return set()

            ips = set()

            logger.info("Parsing Shodan results...")

            try:
                with gzip.open(raw_file, 'rt', encoding='utf-8') as f:
                    for line in f:
                        try:
                            data = json.loads(line.strip())
                            ip = data.get('ip_str')
                            if ip:
                                ips.add(ip)
                        except json.JSONDecodeError:
                            continue
                        except Exception:
                            continue
            except Exception as e:
                logger.error("Error parsing Shodan data: %s", e)
                return set()

            if ips:
                logger.info("Extracted %d unique IPs from Shodan", len(ips))
            else:
                logger.debug("No IPs extracted from Shodan results")

            return ips

    except subprocess.TimeoutExpired:
        logger.warning("Shodan operation timeout")
        return set()

    except FileNotFoundError:
        logger.warning("Shodan CLI not found in PATH")
        return set()

    except Exception as e:
        logger.error("Shodan unexpected error: %s", e)
        return set()


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python3 shodan_ips.py <domain>")
        print("Example: python3 shodan_ips.py abbvie.com")
        sys.exit(1)

    domain = sys.argv[1]

    print(f"[*] Fetching IPs for: {domain}")
    print(f"{'='*60}")

    ips = get_shodan_ips(domain)

    if ips:
        print(f"\n[+] Found {len(ips)} IPs:")
        for ip in sorted(ips):
            print(f"    {ip}")

        output_file = f"{domain}_shodan_ips.txt"
        with open(output_file, 'w') as f:
            for ip in sorted(ips):
                f.write(f"{ip}\n")

        print(f"\n[+] Saved to: {output_file}")
    else:
        print("\n[-] No IPs found")
