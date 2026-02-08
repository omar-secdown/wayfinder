#!/usr/bin/env python3
"""
Wayfinder Configuration File
Loads API keys from .env, validates tools and requirements.
"""

import os
import re
import subprocess
import sys
import urllib.request

from dotenv import load_dotenv

from logger import logger

# ============================================================================
# LOAD API KEYS FROM .env
# ============================================================================

# Load .env from the same directory as this file
_env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env')
load_dotenv(_env_path)

API_KEYS = {
    'OTX_API_KEY': os.environ.get('OTX_API_KEY', ''),
    'SECURITYTRAILS_API_KEY': os.environ.get('SECURITYTRAILS_API_KEY', ''),
    'VIRUSTOTAL_API_KEY': os.environ.get('VIRUSTOTAL_API_KEY', ''),
    'CHAOS_API_KEY': os.environ.get('CHAOS_API_KEY', ''),
    'URLSCAN_API_KEY': os.environ.get('URLSCAN_API_KEY', ''),
}


# ============================================================================
# TOOL PATHS & FILES
# ============================================================================

# Home directory
HOME_DIR = os.path.expanduser('~')

# Required files
RESOLVERS_FILE = os.path.join(HOME_DIR, 'resolvers-trusted.txt')
WORDLIST_FILE = os.path.join(HOME_DIR, 'subdomains-top1million-110000.txt')

# Download URLs
RESOLVERS_URL = 'https://raw.githubusercontent.com/trickest/resolvers/refs/heads/main/resolvers-trusted.txt'
WORDLIST_URL = 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-110000.txt'


# ============================================================================
# REQUIRED TOOLS
# ============================================================================

REQUIRED_TOOLS = {
    'httpx': 'go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest',
    'alterx': 'go install -v github.com/projectdiscovery/alterx/cmd/alterx@latest',
    'shuffledns': 'go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest',
    'subfinder': 'go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest',
    'anew': 'go install -v github.com/tomnomnom/anew@latest',
    'shodan': 'pip install shodan --break-system-packages'
}


# ============================================================================
# DOMAIN VALIDATION
# ============================================================================

# Valid domain regex: letters, digits, hyphens, dots only
_DOMAIN_RE = re.compile(
    r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
)


def validate_domain(domain):
    """
    Validate that a domain string is safe and well-formed.

    Args:
        domain: Domain string to validate

    Returns:
        True if the domain is valid

    Raises:
        ValueError: If the domain is invalid
    """
    if not domain:
        raise ValueError("Domain cannot be empty")
    if len(domain) > 253:
        raise ValueError("Domain exceeds maximum length (253 characters)")
    if not _DOMAIN_RE.match(domain):
        raise ValueError(
            f"Invalid domain format: {domain!r} — "
            "must contain only letters, digits, hyphens, and dots"
        )
    return True


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def check_tool_installed(tool_name):
    """Check if a tool is installed and in PATH"""
    try:
        result = subprocess.run(
            ['which', tool_name],
            capture_output=True,
            text=True
        )
        return result.returncode == 0
    except Exception:
        return False


def check_shodan_configured():
    """Check if Shodan CLI is configured with API key"""
    try:
        result = subprocess.run(
            ['shodan', 'info'],
            capture_output=True,
            text=True,
            timeout=10
        )
        return result.returncode == 0
    except Exception:
        return False


def download_file(url, destination):
    """Download a file from URL to destination"""
    try:
        logger.info("Downloading %s...", os.path.basename(destination))
        urllib.request.urlretrieve(url, destination)
        logger.info("Downloaded to: %s", destination)
        return True
    except Exception as e:
        logger.error("Failed to download: %s", e)
        return False


def check_file_exists(filepath):
    """Check if file exists and is not empty"""
    return os.path.exists(filepath) and os.path.getsize(filepath) > 0


# ============================================================================
# MAIN VALIDATION FUNCTION
# ============================================================================

def validate_requirements(skip_expansion_tools=False):
    """
    Validate all requirements for wayfinder tool

    Args:
        skip_expansion_tools: If True, skip checking alterx/shuffledns/anew

    Returns:
        bool: True if all requirements met, False otherwise
    """
    print("\n" + "="*60)
    print("[*] Validating Wayfinder Requirements...")
    print("="*60 + "\n")

    all_valid = True

    # ========================================
    # 1. Check API Keys
    # ========================================
    print("[+] Checking API Keys...")
    missing_keys = []
    for key_name, key_value in API_KEYS.items():
        if not key_value or key_value == '':
            missing_keys.append(key_name)
            print(f"    [x] {key_name}: NOT SET")
            all_valid = False
        else:
            masked_key = key_value[:10] + "..." if len(key_value) > 10 else key_value
            print(f"    [+] {key_name}: {masked_key}")

    if missing_keys:
        print(f"\n    [!] Missing API keys: {', '.join(missing_keys)}")
        print("    [!] Please configure them in .env (see .env.example)")

    # ========================================
    # 2. Check Required Tools
    # ========================================
    print("\n[+] Checking Required Tools...")

    core_tools = ['httpx', 'subfinder']
    for tool in core_tools:
        if check_tool_installed(tool):
            print(f"    [+] {tool}: Installed")
        else:
            print(f"    [x] {tool}: NOT FOUND")
            print(f"        Install: {REQUIRED_TOOLS[tool]}")
            all_valid = False

    expansion_tools = ['alterx', 'shuffledns', 'anew']
    if not skip_expansion_tools:
        for tool in expansion_tools:
            if check_tool_installed(tool):
                print(f"    [+] {tool}: Installed")
            else:
                print(f"    [x] {tool}: NOT FOUND")
                print(f"        Install: {REQUIRED_TOOLS[tool]}")
                all_valid = False

    if check_tool_installed('shodan'):
        print("    [+] shodan: Installed")
        if check_shodan_configured():
            print("    [+] shodan: Configured with API key")
        else:
            print("    [!] shodan: NOT CONFIGURED")
            print("        Configure with: shodan init YOUR_API_KEY")
            print("        Note: Shodan features will be skipped if not configured")
    else:
        print("    [x] shodan: NOT FOUND")
        print(f"        Install: {REQUIRED_TOOLS['shodan']}")
        all_valid = False

    # ========================================
    # 3. Check/Download Required Files
    # ========================================
    if not skip_expansion_tools:
        print("\n[+] Checking Required Files...")

        if check_file_exists(RESOLVERS_FILE):
            print(f"    [+] Resolvers file: {RESOLVERS_FILE}")
        else:
            print("    [!] Resolvers file not found")
            print("    [*] Attempting to download...")
            if download_file(RESOLVERS_URL, RESOLVERS_FILE):
                print("    [+] Resolvers file ready")
            else:
                print("    [x] Failed to download resolvers file")
                all_valid = False

        if check_file_exists(WORDLIST_FILE):
            print(f"    [+] Wordlist file: {WORDLIST_FILE}")
        else:
            print("    [!] Wordlist file not found")
            print("    [*] Attempting to download...")
            if download_file(WORDLIST_URL, WORDLIST_FILE):
                print("    [+] Wordlist file ready")
            else:
                print("    [x] Failed to download wordlist file")
                all_valid = False

    # ========================================
    # Summary
    # ========================================
    print("\n" + "="*60)
    if all_valid:
        print("[+] All requirements satisfied!")
    else:
        print("[x] Some requirements are missing!")
        print("[!] Please install missing tools/configure API keys")
    print("="*60 + "\n")

    return all_valid


# ============================================================================
# RUN VALIDATION IF EXECUTED DIRECTLY
# ============================================================================

if __name__ == "__main__":
    valid = validate_requirements(skip_expansion_tools=False)
    sys.exit(0 if valid else 1)
