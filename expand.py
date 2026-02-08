#!/usr/bin/env python3
"""
Subdomain Expansion Module
Uses alterx (permutation) and shuffledns (bruteforce) to expand subdomain lists
"""

import os
import shutil
import subprocess
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed

import config
from logger import logger

# Known two-character country-code second-level domains
_CC_SLDS = {
    'co', 'com', 'org', 'net', 'edu', 'gov', 'ac', 'or', 'ne', 'go',
    'mil', 'sch', 'gen', 'biz', 'web', 'info',
}


def run_alterx(input_file, output_file):
    """
    Run alterx for subdomain permutation

    Args:
        input_file: File containing discovered subdomains
        output_file: File to append results to

    Returns:
        int: Number of new subdomains generated
    """
    try:
        logger.info("Running alterx permutation engine...")

        # Safe pipe: cat -> alterx -> anew, no shell=True
        cat_proc = subprocess.Popen(
            ['cat', input_file],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        alterx_proc = subprocess.Popen(
            ['alterx'],
            stdin=cat_proc.stdout,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        cat_proc.stdout.close()
        anew_proc = subprocess.Popen(
            ['anew', output_file],
            stdin=alterx_proc.stdout,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        alterx_proc.stdout.close()

        stdout, _ = anew_proc.communicate(timeout=300)
        cat_proc.wait()
        alterx_proc.wait()

        new_count = len([line for line in stdout.decode().strip().split('\n') if line.strip()])

        logger.info("alterx: Generated %d new permutations", new_count)
        return new_count

    except subprocess.TimeoutExpired:
        logger.warning("alterx timeout")
        return 0
    except Exception as e:
        logger.error("alterx error: %s", e)
        return 0


def run_shuffledns(domain, output_file):
    """
    Run shuffledns for single domain bruteforce

    Args:
        domain: Single domain to bruteforce
        output_file: File to append results to

    Returns:
        int: Number of new subdomains found
    """
    try:
        # Create temporary output file for shuffledns
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as temp_file:
            temp_output = temp_file.name

        # shuffledns command
        command = [
            'shuffledns',
            '-d', domain,
            '-w', config.WORDLIST_FILE,
            '-r', config.RESOLVERS_FILE,
            '-mode', 'bruteforce',
            '-o', temp_output,
            '-silent'
        ]

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=600  # 10 minutes timeout per domain
        )

        if result.returncode != 0:
            stderr_lower = result.stderr.lower()
            if 'no such file' in stderr_lower:
                logger.warning("Missing wordlist or resolvers file")
            elif 'permission denied' in stderr_lower:
                logger.warning("Permission error")
            else:
                logger.warning("shuffledns error: %s", result.stderr.strip())

            if os.path.exists(temp_output):
                os.remove(temp_output)
            return 0

        # Use anew to append unique results to output file (safe pipe)
        if os.path.exists(temp_output) and os.path.getsize(temp_output) > 0:
            cat_proc = subprocess.Popen(
                ['cat', temp_output],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            )
            anew_proc = subprocess.Popen(
                ['anew', output_file],
                stdin=cat_proc.stdout,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            )
            cat_proc.stdout.close()

            stdout, _ = anew_proc.communicate(timeout=60)
            cat_proc.wait()

            new_count = len([line for line in stdout.decode().strip().split('\n') if line.strip()])

            os.remove(temp_output)
            return new_count
        else:
            if os.path.exists(temp_output):
                os.remove(temp_output)
            return 0

    except subprocess.TimeoutExpired:
        logger.warning("shuffledns timeout for %s", domain)
        return 0
    except Exception as e:
        logger.error("shuffledns error for %s: %s", domain, e)
        return 0


def expand_subdomains(input_file, output_file, domains_list=None):
    """
    Expand subdomains using alterx and shuffledns in parallel

    Args:
        input_file: File containing discovered subdomains (all_subdomains.txt)
        output_file: Output file for expansion results (all_in_one.txt)
        domains_list: List of root domains for shuffledns (extracted from input_file)

    Returns:
        int: Total number of new subdomains discovered
    """
    print(f"\n{'='*60}")
    print(f"[+] Starting Subdomain Expansion")
    print(f"{'='*60}\n")

    if not os.path.exists(input_file):
        logger.error("Input file not found: %s", input_file)
        return 0

    if not os.path.exists(config.WORDLIST_FILE):
        logger.error("Wordlist not found: %s", config.WORDLIST_FILE)
        return 0

    if not os.path.exists(config.RESOLVERS_FILE):
        logger.error("Resolvers file not found: %s", config.RESOLVERS_FILE)
        return 0

    # Copy input file to output file first (seed data) — safe copy
    shutil.copy2(input_file, output_file)

    total_new = 0

    # ========================================
    # Step 1: Run alterx
    # ========================================
    print(f"[1/2] Running alterx permutation...")
    alterx_count = run_alterx(input_file, output_file)
    total_new += alterx_count

    # ========================================
    # Step 2: Run shuffledns for each domain
    # ========================================
    shuffledns_total = 0
    if domains_list and len(domains_list) > 0:
        print(f"\n[2/2] Running shuffledns bruteforce on {len(domains_list)} domains...")
        print(f"[*] This may take a while depending on wordlist size...\n")

        completed = 0

        with ThreadPoolExecutor(max_workers=2) as executor:
            future_to_domain = {
                executor.submit(run_shuffledns, domain, output_file): domain
                for domain in domains_list
            }

            for future in as_completed(future_to_domain):
                domain = future_to_domain[future]
                completed += 1

                try:
                    new_count = future.result()
                    shuffledns_total += new_count
                    print(f"    [{completed}/{len(domains_list)}] + {domain}: +{new_count} subdomains")
                except Exception as e:
                    logger.error("[%d/%d] %s: Error - %s", completed, len(domains_list), domain, e)

        total_new += shuffledns_total
        logger.info("shuffledns: Found %d new subdomains across all domains", shuffledns_total)
    else:
        print(f"\n[2/2] Skipping shuffledns (no root domains provided)")

    # ========================================
    # Summary
    # ========================================
    print(f"\n{'='*60}")
    print(f"[+] Expansion Complete!")
    print(f"    - alterx permutations: +{alterx_count}")
    if domains_list:
        print(f"    - shuffledns bruteforce: +{shuffledns_total}")
    print(f"    - Total new subdomains: {total_new}")

    if os.path.exists(output_file):
        with open(output_file, 'r') as f:
            total_count = sum(1 for line in f if line.strip())
        print(f"    - Total subdomains in output: {total_count}")

    print(f"[+] Results saved to: {output_file}")
    print(f"{'='*60}\n")

    return total_new


def extract_root_domains(subdomains_file):
    """
    Extract unique root domains from subdomains list.
    Handles country-code TLDs like .co.uk, .com.au, .edu.eg.

    Args:
        subdomains_file: File containing subdomains

    Returns:
        list: Unique root domains (e.g., ['example.com', 'example.co.uk'])
    """
    root_domains = set()

    try:
        with open(subdomains_file, 'r') as f:
            for line in f:
                subdomain = line.strip()
                if not subdomain:
                    continue

                parts = subdomain.split('.')
                if len(parts) < 2:
                    continue

                # Check for cc-SLD pattern: e.g. .co.uk, .com.au, .edu.eg
                # If the second-level part is a known SLD and the TLD is 2 chars
                if (
                    len(parts) >= 3
                    and len(parts[-1]) == 2
                    and parts[-2] in _CC_SLDS
                ):
                    root_domain = '.'.join(parts[-3:])
                else:
                    root_domain = '.'.join(parts[-2:])

                root_domains.add(root_domain)

        return sorted(list(root_domains))

    except Exception as e:
        logger.error("Error extracting root domains: %s", e)
        return []


# ============================================================================
# FOR STANDALONE TESTING
# ============================================================================

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python3 expand.py <subdomains_file>")
        print("Example: python3 expand.py all_subdomains.txt")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = "all_in_one.txt"

    # Extract root domains
    domains = extract_root_domains(input_file)
    print(f"[*] Found {len(domains)} unique root domains: {', '.join(domains)}")

    # Run expansion
    expand_subdomains(input_file, output_file, domains)
