import subprocess
import tempfile
import os

from logger import logger


def _matches_domain(hostname, domain):
    """Proper suffix-based domain matching."""
    return hostname == domain or hostname.endswith('.' + domain)


def get_subfinder_subdomains(domain):
    """
    Fetch subdomains using subfinder with -all flag.
    Subfinder is a subdomain discovery tool by ProjectDiscovery.

    Args:
        domain: Target domain to enumerate

    Returns:
        List of unique subdomains or empty list on failure
    """
    try:
        check_subfinder = subprocess.run(
            ['which', 'subfinder'],
            capture_output=True,
            text=True
        )

        if check_subfinder.returncode != 0:
            logger.warning("subfinder not found! Install it with: "
                           "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")
            return []

        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as temp_file:
            temp_output = temp_file.name

        command = [
            'subfinder',
            '-d', domain,
            '-all',
            '-o', temp_output,
            '-silent'
        ]

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            stderr_lower = result.stderr.lower()
            if 'not found' in stderr_lower or 'command not found' in stderr_lower:
                logger.warning("subfinder not found in PATH")
            elif result.stderr.strip():
                logger.warning("subfinder error: %s", result.stderr.strip())

            if os.path.exists(temp_output):
                os.remove(temp_output)
            return []

        subdomains = []
        if os.path.exists(temp_output) and os.path.getsize(temp_output) > 0:
            with open(temp_output, 'r') as f:
                for line in f:
                    subdomain = line.strip()
                    if subdomain and _matches_domain(subdomain, domain):
                        subdomains.append(subdomain)

        if os.path.exists(temp_output):
            os.remove(temp_output)

        return subdomains

    except FileNotFoundError:
        logger.warning("subfinder not found in PATH")
        return []

    except Exception as e:
        logger.error("subfinder unexpected error: %s", e)
        return []


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python3 subfinder_subs.py <domain>")
        print("Example: python3 subfinder_subs.py example.com")
        sys.exit(1)

    domain = sys.argv[1]

    print(f"[*] Fetching subdomains for: {domain}")
    print(f"{'='*60}")

    subs = get_subfinder_subdomains(domain)

    if subs:
        print(f"\n[+] Found {len(subs)} subdomains:")
        for sub in sorted(subs):
            print(f"    {sub}")

        output_file = f"{domain}_subfinder_subs.txt"
        with open(output_file, 'w') as f:
            for sub in sorted(subs):
                f.write(f"{sub}\n")

        print(f"\n[+] Saved to: {output_file}")
    else:
        print("\n[-] No subdomains found")
