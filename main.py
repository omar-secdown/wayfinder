#!/usr/bin/env python3
import argparse
import sys
import os
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

import config
from logger import logger, set_verbose

# Import subdomain modules
from subdomain_modules.shodan_subs import download_and_parse_shodan_data
from subdomain_modules.virustotal_subs import get_virustotal_subdomains
from subdomain_modules.securitytrails_subs import get_securitytrails_subdomains
from subdomain_modules.crtsh_subs import get_crtsh_subdomains
from subdomain_modules.chaos_subs import get_chaos_subdomains
from subdomain_modules.urlscan_subs import get_urlscan_subdomains
from subdomain_modules.otx_subs import get_otx_subdomains
from subdomain_modules.subfinder_subs import get_subfinder_subdomains

# Import acquisition modules
from acquisition.securitytrails_acq import get_securitytrails_associated
from acquisition.otx_acq import get_otx_associated

# Import IP modules
from ip_modules.securitytrails_ips import get_securitytrails_cidrs, expand_cidrs_to_ips, save_cidrs_to_file
from ip_modules.shodan_ips import get_shodan_ips

# Import expansion module
import expand


def check_live_subdomains(input_file, output_file):
    import subprocess

    try:
        check_httpx = subprocess.run(['which', 'httpx'], capture_output=True, text=True)

        if check_httpx.returncode != 0:
            logger.error("httpx not found! Required for -live flag")
            print("    Install with: go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest")
            print("    Or run: ./setup.sh\n")
            return 0

        command = [
            'httpx',
            '-l', input_file,
            '-silent',
            '-no-color',
            '-timeout', '10',
            '-threads', '50',
            '-o', output_file
        ]

        result = subprocess.run(command, capture_output=True, text=True, timeout=600)

        if result.returncode != 0:
            logger.error("httpx error: %s", result.stderr)
            return 0

        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                live_count = sum(1 for line in f if line.strip())
            return live_count
        else:
            return 0

    except Exception as e:
        logger.error("Error running httpx: %s", e)
        return 0


def validate_expansion_tools():
    """
    Validate expansion tools (alterx, shuffledns, anew) only when -expand is used
    Returns True if all tools available, False otherwise
    """
    print("\n[*] Validating expansion tools (alterx, shuffledns, anew)...")

    required_tools = ['alterx', 'shuffledns', 'anew']
    missing_tools = []

    for tool in required_tools:
        if not config.check_tool_installed(tool):
            missing_tools.append(tool)
            print(f"    [x] {tool}: NOT FOUND")
        else:
            print(f"    [+] {tool}: Installed")

    if not os.path.exists(config.RESOLVERS_FILE):
        logger.error("Resolvers file not found: %s", config.RESOLVERS_FILE)
        print(f"        Download with: python3 config.py")
        return False
    else:
        print(f"    [+] Resolvers file: {config.RESOLVERS_FILE}")

    if not os.path.exists(config.WORDLIST_FILE):
        logger.error("Wordlist not found: %s", config.WORDLIST_FILE)
        print(f"        Download with: python3 config.py")
        return False
    else:
        print(f"    [+] Wordlist file: {config.WORDLIST_FILE}")

    if missing_tools:
        logger.error("Missing tools: %s", ', '.join(missing_tools))
        print(f"[!] Install with: ./setup.sh")
        print(f"[!] Or install individually:")
        for tool in missing_tools:
            print(f"    {config.REQUIRED_TOOLS.get(tool, 'N/A')}")
        print()
        return False

    print("[+] All expansion tools ready!\n")
    return True


def fetch_subdomains_parallel(domain):
    """
    Fetch subdomains from all sources in parallel.
    Returns a dictionary with source names and their results.
    """
    tasks = {
        'VirusTotal': lambda: get_virustotal_subdomains(domain),
        'SecurityTrails': lambda: get_securitytrails_subdomains(domain),
        'crt.sh': lambda: get_crtsh_subdomains(domain),
        'Shodan': lambda: download_and_parse_shodan_data(domain),
        'Chaos': lambda: get_chaos_subdomains(domain),
        'URLScan': lambda: get_urlscan_subdomains(domain),
        'AlienVault OTX': lambda: get_otx_subdomains(domain),
        'Subfinder': lambda: get_subfinder_subdomains(domain)
    }

    results = {}
    all_subdomains = set()

    print(f"[+] Fetching subdomains from {len(tasks)} sources in parallel...")
    print(f"[*] This will be much faster than sequential queries!\n")

    start_time = time.time()
    completed = 0
    total = len(tasks)

    with ThreadPoolExecutor(max_workers=8) as executor:
        future_to_source = {executor.submit(task): source for source, task in tasks.items()}

        for future in as_completed(future_to_source):
            source = future_to_source[future]
            completed += 1
            try:
                result = future.result() or []
                results[source] = result
                all_subdomains.update(result)
                print(f"[{completed}/{total}] + {source}: {len(result)} subdomains")
            except Exception as e:
                logger.error("[%d/%d] %s: Error - %s", completed, total, source, e)
                results[source] = []

    elapsed = time.time() - start_time
    print(f"\n[*] All sources completed in {elapsed:.2f} seconds")

    return all_subdomains, results


def subdomain_enumeration(domain, output_dir, check_live=False, run_expansion=False):
    """
    Core subdomain enumeration function for both single-domain and batch modes.

    Args:
        domain: Target domain
        output_dir: Directory to write results into
        check_live: Whether to check for live hosts with httpx
        run_expansion: Whether to run alterx + shuffledns expansion

    Returns:
        (all_subdomains, live_subdomains) tuple of sets
    """
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    subs_file = os.path.join(output_dir, 'subdomains.txt')
    live_file = os.path.join(output_dir, 'live_subdomains.txt')

    print(f"\n{'='*60}")
    print(f"[*] Target: {domain}")
    print(f"{'='*60}\n")

    # Fetch all subdomains in parallel
    all_subdomains, source_results = fetch_subdomains_parallel(domain)

    # Save all subdomains
    with open(subs_file, 'w') as file:
        for subdomain in sorted(all_subdomains):
            file.write(f"{subdomain}\n")

    print(f"\n{'='*60}")
    print(f"[+] Total unique subdomains: {len(all_subdomains)}")
    print(f"[+] Saved to: {subs_file}")

    # Run expansion if requested
    if run_expansion:
        if not validate_expansion_tools():
            logger.warning("Expansion tools not available. Skipping expansion.")
        else:
            all_in_one_file = os.path.join(output_dir, 'all_in_one.txt')
            domains_list = [domain]
            expand.expand_subdomains(subs_file, all_in_one_file, domains_list)

            if check_live:
                live_expansion_file = os.path.join(output_dir, 'live_all_in_one.txt')
                print(f"\n[+] Checking expanded subdomains for live hosts with httpx...")
                live_count = check_live_subdomains(all_in_one_file, live_expansion_file)
                print(f"[+] Live expanded subdomains: {live_count}")
                print(f"[+] Saved to: {live_expansion_file}")

    live_subdomains = set()
    if check_live:
        print(f"\n[+] Checking for live subdomains with httpx...")
        live_count = check_live_subdomains(subs_file, live_file)
        print(f"[+] Live subdomains: {live_count}")
        print(f"[+] Saved to: {live_file}")

        if os.path.exists(live_file):
            with open(live_file, 'r') as f:
                live_subdomains = set(line.strip() for line in f if line.strip())

    print(f"{'='*60}\n")

    return all_subdomains, live_subdomains


def process_single_domain(domain, check_live=False, run_expansion=False):
    """Thin wrapper: runs subdomain_enumeration with quick_results output dir."""
    output_dir = os.path.join(os.getcwd(), 'output', 'quick_results', domain)
    subdomain_enumeration(domain, output_dir, check_live, run_expansion)


def ip_enumeration(domain, ip_output_dir):
    if not os.path.exists(ip_output_dir):
        os.makedirs(ip_output_dir)

    now = datetime.now()
    date_suffix = now.strftime('%d_%m')
    ips_file = os.path.join(ip_output_dir, f'ips_for_{domain}_{date_suffix}.txt')

    print(f"\n{'='*60}")
    print(f"[*] IP Enumeration for: {domain}")
    print(f"{'='*60}\n")

    all_ips = set()

    tasks = {
        'SecurityTrails CIDRs': lambda: get_securitytrails_cidrs(domain),
        'Shodan SSL': lambda: get_shodan_ips(domain)
    }

    print(f"[+] Fetching IPs from sources in parallel...\n")

    st_cidrs = []
    shodan_ips = set()

    with ThreadPoolExecutor(max_workers=2) as executor:
        future_to_source = {executor.submit(task): source for source, task in tasks.items()}

        for future in as_completed(future_to_source):
            source = future_to_source[future]
            try:
                result = future.result()
                if source == 'SecurityTrails CIDRs':
                    st_cidrs = result or []
                    print(f"[+] SecurityTrails: {len(st_cidrs)} CIDRs")
                else:
                    shodan_ips = result or set()
                    print(f"[+] Shodan: {len(shodan_ips)} IPs")
            except Exception as e:
                logger.error("%s: Error - %s", source, e)

    if st_cidrs:
        print(f"\n[+] Expanding CIDRs to individual IPs...")
        expanded_ips = expand_cidrs_to_ips(st_cidrs, max_ips_per_cidr=10000)
        all_ips.update(expanded_ips)

    all_ips.update(shodan_ips)

    if all_ips:
        with open(ips_file, 'w') as f:
            for ip in sorted(all_ips):
                f.write(f"{ip}\n")

        print(f"\n[+] Total IPs saved to: {ips_file}")
    else:
        logger.warning("No IPs found")

    print(f"\n{'='*60}")
    print(f"[+] Total unique IPs: {len(all_ips)}")
    print(f"[+] Ready for scanning with masscan/nmap")
    print(f"{'='*60}\n")

    return all_ips


def process_domain_list(list_file, check_live=False, parallel_domains=3, run_expansion=False):
    if not os.path.exists(list_file):
        logger.error("File '%s' not found!", list_file)
        return

    with open(list_file, 'r') as f:
        domains = [line.strip() for line in f if line.strip()]

    if not domains:
        logger.error("No domains found in list!")
        return

    # Validate all domains up front
    for d in domains:
        try:
            config.validate_domain(d)
        except ValueError as e:
            logger.error("Invalid domain in list: %s", e)
            return

    first_domain = domains[0]
    date_prefix = datetime.now().strftime('%Y-%m-%d')
    scan_name = f"{date_prefix}_{first_domain}"

    scan_dir = os.path.join(os.getcwd(), 'output', 'scans', scan_name)
    if not os.path.exists(scan_dir):
        os.makedirs(scan_dir)

    print(f"\n[*] Scan directory: {scan_dir}")
    print(f"[*] Processing {len(domains)} domains from list...")
    print(f"[*] Running {parallel_domains} domains in parallel for speed\n")

    all_subdomains_aggregate = set()
    all_live_aggregate = set()

    start_time = time.time()

    with ThreadPoolExecutor(max_workers=parallel_domains) as executor:
        futures = []
        for idx, domain in enumerate(domains, 1):
            domain_dir = os.path.join(scan_dir, domain)
            future = executor.submit(subdomain_enumeration, domain, domain_dir, check_live)
            futures.append((future, domain, idx))

        for future, domain, idx in futures:
            print(f"\n{'#'*60}")
            print(f"[*] Collecting results for domain {idx}/{len(domains)}: {domain}")
            print(f"{'#'*60}")

            try:
                domain_subs, domain_live = future.result()
                all_subdomains_aggregate.update(domain_subs)
                all_live_aggregate.update(domain_live)
            except Exception as e:
                logger.error("Error processing %s: %s", domain, e)
                continue

    elapsed = time.time() - start_time
    print(f"\n[*] Total scan time: {elapsed:.2f} seconds ({elapsed/60:.2f} minutes)")

    print(f"\n{'='*60}")
    print(f"[*] Saving aggregated results...")
    print(f"{'='*60}\n")

    all_subs_file = os.path.join(scan_dir, 'all_subdomains.txt')
    with open(all_subs_file, 'w') as f:
        for subdomain in sorted(all_subdomains_aggregate):
            f.write(f"{subdomain}\n")

    print(f"[+] All subdomains from all domains: {len(all_subdomains_aggregate)}")
    print(f"[+] Saved to: {all_subs_file}")

    if run_expansion:
        if not validate_expansion_tools():
            logger.warning("Expansion tools not available. Skipping expansion.")
        else:
            all_in_one_file = os.path.join(scan_dir, 'all_in_one.txt')
            expand.expand_subdomains(all_subs_file, all_in_one_file, domains)

            if check_live:
                live_expansion_file = os.path.join(scan_dir, 'live_all_in_one.txt')
                print(f"\n[+] Checking expanded subdomains for live hosts with httpx...")
                live_count = check_live_subdomains(all_in_one_file, live_expansion_file)
                print(f"[+] Live expanded subdomains: {live_count}")
                print(f"[+] Saved to: {live_expansion_file}")

    if check_live and all_live_aggregate:
        all_live_file = os.path.join(scan_dir, 'live_all_subdomains.txt')
        with open(all_live_file, 'w') as f:
            for subdomain in sorted(all_live_aggregate):
                f.write(f"{subdomain}\n")

        print(f"[+] All live subdomains from all domains: {len(all_live_aggregate)}")
        print(f"[+] Saved to: {all_live_file}")

    print(f"\n{'='*60}")
    print(f"[+] Scan complete! Results saved in: {scan_dir}")
    print(f"{'='*60}\n")


def process_ip_single(domain):
    ip_output_dir = os.path.join(os.getcwd(), 'output', 'ips')
    ip_enumeration(domain, ip_output_dir)


def process_ip_list(list_file):
    if not os.path.exists(list_file):
        logger.error("File '%s' not found!", list_file)
        return

    with open(list_file, 'r') as f:
        domains = [line.strip() for line in f if line.strip()]

    if not domains:
        logger.error("No domains found in list!")
        return

    ip_output_dir = os.path.join(os.getcwd(), 'output', 'ips')

    print(f"\n{'#'*60}")
    print(f"[*] Starting IP enumeration for {len(domains)} domains...")
    print(f"{'#'*60}\n")

    for idx, domain in enumerate(domains, 1):
        print(f"[*] IP Enumeration {idx}/{len(domains)}: {domain}")
        try:
            ip_enumeration(domain, ip_output_dir)
        except Exception as e:
            logger.error("Error during IP enumeration for %s: %s", domain, e)
            continue


def process_ip_enum_single(domain, check_live=False):
    process_single_domain(domain, check_live)

    print(f"\n{'#'*60}")
    print(f"[*] Starting IP enumeration phase...")
    print(f"{'#'*60}\n")
    process_ip_single(domain)


def process_ip_enum_list(list_file, check_live=False):
    process_domain_list(list_file, check_live)

    print(f"\n{'#'*60}")
    print(f"[*] Starting IP enumeration phase...")
    print(f"{'#'*60}\n")
    process_ip_list(list_file)


def process_acquisition(domain, email_filters=None):
    output_dir = os.path.join(os.getcwd(), 'output', 'acquisition')
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    acq_file = os.path.join(output_dir, f'{domain}_acquisition.txt')

    all_associated = set()

    print(f"\n{'='*60}")
    print(f"[*] Target: {domain}")
    print(f"[*] Finding associated domains...")
    if email_filters:
        print(f"[*] Email filters: {', '.join(email_filters)}")
    print(f"{'='*60}\n")

    tasks = {
        'SecurityTrails': lambda: get_securitytrails_associated(domain),
        'AlienVault OTX': lambda: get_otx_associated(domain, email_filters)
    }

    print(f"[+] Fetching associated domains from sources in parallel...\n")

    with ThreadPoolExecutor(max_workers=2) as executor:
        future_to_source = {executor.submit(task): source for source, task in tasks.items()}

        for future in as_completed(future_to_source):
            source = future_to_source[future]
            try:
                result = future.result() or []
                all_associated.update(result)
                print(f"[+] {source}: {len(result)} associated domains")
            except Exception as e:
                logger.error("%s: Error - %s", source, e)

    with open(acq_file, 'w') as f:
        for associated_domain in sorted(all_associated):
            f.write(f"{associated_domain}\n")

    print(f"\n{'='*60}")
    print(f"[+] Total associated domains: {len(all_associated)}")
    print(f"[+] Saved to: {acq_file}")
    print(f"{'='*60}\n")


def process_acquisition_with_enum(domain, email_filters=None, check_live=False, parallel_domains=3, run_expansion=False):
    date_prefix = datetime.now().strftime('%Y-%m-%d')
    scan_name = f"{date_prefix}_{domain}_acquisition"

    scan_dir = os.path.join(os.getcwd(), 'output', 'scans', scan_name)
    if not os.path.exists(scan_dir):
        os.makedirs(scan_dir)

    print(f"\n[*] Scan directory: {scan_dir}")

    all_associated = set()

    print(f"\n{'='*60}")
    print(f"[*] Target: {domain}")
    print(f"[*] Phase 1: Finding associated domains...")
    if email_filters:
        print(f"[*] Email filters: {', '.join(email_filters)}")
    print(f"{'='*60}\n")

    tasks = {
        'SecurityTrails': lambda: get_securitytrails_associated(domain),
        'AlienVault OTX': lambda: get_otx_associated(domain, email_filters)
    }

    print(f"[+] Fetching associated domains from sources in parallel...\n")

    with ThreadPoolExecutor(max_workers=2) as executor:
        future_to_source = {executor.submit(task): source for source, task in tasks.items()}

        for future in as_completed(future_to_source):
            source = future_to_source[future]
            try:
                result = future.result() or []
                all_associated.update(result)
                print(f"[+] {source}: {len(result)} associated domains")
            except Exception as e:
                logger.error("%s: Error - %s", source, e)

    assoc_file = os.path.join(scan_dir, 'associated_domains.txt')
    with open(assoc_file, 'w') as f:
        for associated_domain in sorted(all_associated):
            f.write(f"{associated_domain}\n")

    print(f"\n[+] Total associated domains: {len(all_associated)}")
    print(f"[+] Saved to: {assoc_file}")

    if not all_associated:
        logger.warning("No associated domains found. Exiting.")
        return

    print(f"\n{'='*60}")
    print(f"[*] Phase 2: Enumerating subdomains for {len(all_associated)} associated domains...")
    print(f"[*] Running {parallel_domains} domains in parallel for speed")
    print(f"{'='*60}\n")

    all_subdomains_aggregate = set()
    all_live_aggregate = set()

    start_time = time.time()

    with ThreadPoolExecutor(max_workers=parallel_domains) as executor:
        futures = []
        for idx, assoc_domain in enumerate(sorted(all_associated), 1):
            domain_dir = os.path.join(scan_dir, assoc_domain)
            future = executor.submit(subdomain_enumeration, assoc_domain, domain_dir, check_live)
            futures.append((future, assoc_domain, idx))

        for future, assoc_domain, idx in futures:
            print(f"\n{'#'*60}")
            print(f"[*] Collecting results for domain {idx}/{len(all_associated)}: {assoc_domain}")
            print(f"{'#'*60}")

            try:
                domain_subs, domain_live = future.result()
                all_subdomains_aggregate.update(domain_subs)
                all_live_aggregate.update(domain_live)
            except Exception as e:
                logger.error("Error processing %s: %s", assoc_domain, e)
                continue

    elapsed = time.time() - start_time
    print(f"\n[*] Enumeration phase completed in: {elapsed:.2f} seconds ({elapsed/60:.2f} minutes)")

    print(f"\n{'='*60}")
    print(f"[*] Saving aggregated results...")
    print(f"{'='*60}\n")

    all_subs_file = os.path.join(scan_dir, 'all_subdomains.txt')
    with open(all_subs_file, 'w') as f:
        for subdomain in sorted(all_subdomains_aggregate):
            f.write(f"{subdomain}\n")

    print(f"[+] All subdomains from all associated domains: {len(all_subdomains_aggregate)}")
    print(f"[+] Saved to: {all_subs_file}")

    if run_expansion:
        if not validate_expansion_tools():
            logger.warning("Expansion tools not available. Skipping expansion.")
        else:
            all_in_one_file = os.path.join(scan_dir, 'all_in_one.txt')
            expand.expand_subdomains(all_subs_file, all_in_one_file, list(all_associated))

            if check_live:
                live_expansion_file = os.path.join(scan_dir, 'live_all_in_one.txt')
                print(f"\n[+] Checking expanded subdomains for live hosts with httpx...")
                live_count = check_live_subdomains(all_in_one_file, live_expansion_file)
                print(f"[+] Live expanded subdomains: {live_count}")
                print(f"[+] Saved to: {live_expansion_file}")

    if check_live and all_live_aggregate:
        all_live_file = os.path.join(scan_dir, 'live_all_subdomains.txt')
        with open(all_live_file, 'w') as f:
            for subdomain in sorted(all_live_aggregate):
                f.write(f"{subdomain}\n")

        print(f"[+] All live subdomains from all associated domains: {len(all_live_aggregate)}")
        print(f"[+] Saved to: {all_live_file}")

    print(f"\n{'='*60}")
    print(f"[+] Acquisition + Enumeration complete! Results saved in: {scan_dir}")
    print(f"{'='*60}\n")


def main():
    banner = """
    +=======================================================+
    |         Subdomain Enumeration Tool v4.0               |
    |         Bug Bounty Hunter Edition (PARALLEL)          |
    |                                                       |
    |  Sources: VirusTotal, SecurityTrails, crt.sh,         |
    |           Shodan, Chaos, URLScan, AlienVault OTX,     |
    |           Subfinder (ProjectDiscovery)                |
    |                                                       |
    |  Acquisition: SecurityTrails + AlienVault OTX         |
    |  IP Enumeration: SecurityTrails + Shodan (SSL)        |
    |  Expansion: alterx + shuffledns                       |
    |                                                       |
    |  PERFORMANCE: All API calls run in parallel!          |
    |  Output Structure: Hybrid (Organized & Clean)         |
    +=======================================================+
    """
    print(banner)

    parser = argparse.ArgumentParser(
        description="Subdomain Enumeration, Domain Acquisition & IP Enumeration Tool (Parallel Edition)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 main.py -u example.com
  python3 main.py -l domains.txt
  python3 main.py -u example.com -live
  python3 main.py -l domains.txt -expand
  python3 main.py -l domains.txt -expand -live
  python3 main.py -l domains.txt -pd 5
  python3 main.py -ips-d example.com
  python3 main.py -ips-l targets.txt
  python3 main.py -ips-enum-d example.com
  python3 main.py -ips-enum-l targets.txt
  python3 main.py -ips-enum-d example.com -live
  python3 main.py -acq example.com
  python3 main.py -acq example.com -email abbvie,caterpillar
  python3 main.py -acq-enum example.com -live -pd 5 -expand
  python3 main.py -u example.com -v


Output Structure:
  output/
  |-- quick_results/              (Single domain scans: -u)
  |   |-- example.com/
  |   |   |-- subdomains.txt
  |   |   |-- all_in_one.txt              (if -expand used)
  |   |   |-- live_all_in_one.txt         (if -expand -live used)
  |   |   +-- live_subdomains.txt
  |
  |-- scans/                      (Batch/complex scans: -l, -acq-enum)
  |   +-- 2026-01-05_example.com/
  |
  |-- acquisition/                (Acquisition results: -acq)
  |   +-- example.com_acquisition.txt
  |
  +-- ips/                        (IP enumeration results)
      +-- ips_for_example.com_05_01.txt
        """
    )

    group = parser.add_mutually_exclusive_group(required=True)

    group.add_argument('-u', '--url', type=str, help="Single target domain")
    group.add_argument('-l', '--list', type=str, help="File containing list of domains")
    group.add_argument('-ips-d', '--ip-domain', type=str, metavar='DOMAIN', help="IP enumeration for single domain")
    group.add_argument('-ips-l', '--ip-list', type=str, metavar='FILE', help="IP enumeration for list of domains")
    group.add_argument('-ips-enum-d', '--ip-enum-domain', type=str, metavar='DOMAIN', help="Subdomain + IP enumeration for single domain")
    group.add_argument('-ips-enum-l', '--ip-enum-list', type=str, metavar='FILE', help="Subdomain + IP enumeration for list of domains")
    group.add_argument('-acq', '--acquisition', type=str, metavar='DOMAIN', help="Find associated domains")
    group.add_argument('-acq-enum', '--acquisition-enum', type=str, metavar='DOMAIN', help="Find associated domains AND enumerate subdomains")

    parser.add_argument('-live', '--live', action='store_true', help="Check for live subdomains using httpx")
    parser.add_argument('-expand', '--expand', action='store_true', help="Run subdomain expansion (alterx + shuffledns)")
    parser.add_argument('-email', '--email-filters', type=str, metavar='DOMAINS', help="Comma-separated email domain names for acquisition")
    parser.add_argument('-pd', '--parallel-domains', type=int, default=3, metavar='N', help="Number of domains to process in parallel (default: 3)")
    parser.add_argument('-v', '--verbose', action='store_true', help="Enable verbose/debug output")

    args = parser.parse_args()

    # Enable verbose logging if requested
    if args.verbose:
        set_verbose(True)
        logger.debug("Verbose mode enabled")

    # Quick validation: Only check API keys (fast)
    missing_keys = []
    for key_name, key_value in config.API_KEYS.items():
        if not key_value or key_value == '':
            missing_keys.append(key_name)

    if missing_keys:
        logger.warning("Missing API keys: %s", ', '.join(missing_keys))
        print("[!] Please configure them in .env (see .env.example)")
        print("[!] Run 'python3 config.py' for detailed validation\n")
        sys.exit(1)

    # Determine the target domain(s) and validate
    target_domain = (
        args.url
        or args.ip_domain
        or args.ip_enum_domain
        or args.acquisition
        or args.acquisition_enum
    )
    if target_domain:
        try:
            config.validate_domain(target_domain)
        except ValueError as e:
            logger.error("Invalid domain: %s", e)
            sys.exit(1)

    email_filters = None
    if args.email_filters:
        email_filters = [f.strip() for f in args.email_filters.split(',') if f.strip()]
        if not email_filters:
            logger.error("No valid email filters provided!")
            return

    if args.url:
        process_single_domain(args.url, args.live, args.expand)
    elif args.list:
        process_domain_list(args.list, args.live, args.parallel_domains, args.expand)
    elif args.ip_domain:
        process_ip_single(args.ip_domain)
    elif args.ip_list:
        process_ip_list(args.ip_list)
    elif args.ip_enum_domain:
        process_ip_enum_single(args.ip_enum_domain, args.live)
    elif args.ip_enum_list:
        process_ip_enum_list(args.ip_enum_list, args.live)
    elif args.acquisition:
        process_acquisition(args.acquisition, email_filters)
    elif args.acquisition_enum:
        process_acquisition_with_enum(args.acquisition_enum, email_filters, args.live, args.parallel_domains, args.expand)

    print("\n[+] All operations completed!")


if __name__ == "__main__":
    main()
