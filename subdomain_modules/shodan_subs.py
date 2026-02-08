import os
import subprocess
import tempfile

from logger import logger


def _matches_domain(hostname, domain):
    """Proper suffix-based domain matching."""
    return hostname == domain or hostname.endswith('.' + domain)


def download_and_parse_shodan_data(domain):
    """
    Download and parse subdomain data from Shodan.
    Requires Shodan CLI to be installed and configured.

    Args:
        domain: Target domain to enumerate

    Returns:
        List of unique subdomains or empty list on failure
    """
    try:
        check_shodan = subprocess.run(
            ['which', 'shodan'],
            capture_output=True,
            text=True
        )

        if check_shodan.returncode != 0:
            logger.warning("Shodan CLI not found! Install it with: pip install shodan")
            return []

        with tempfile.TemporaryDirectory() as temp_dir:
            raw_file = os.path.join(temp_dir, f"{domain}_results.json.gz")
            parsed_file = os.path.join(temp_dir, f"{domain}_hosts.txt")

            download_command = [
                'shodan', 'download',
                '--limit', '-1',
                raw_file,
                f'hostname:{domain}'
            ]

            download_result = subprocess.run(
                download_command,
                capture_output=True,
                text=True,
                timeout=300
            )

            if download_result.returncode != 0:
                if 'Please provide your Shodan API key' in download_result.stderr:
                    logger.warning("Shodan API key not configured")
                else:
                    logger.warning("Shodan download error: %s", download_result.stderr.strip())
                return []

            if not os.path.exists(raw_file) or os.path.getsize(raw_file) == 0:
                logger.debug("No Shodan results found for %s", domain)
                return []

            # Safe pipe: shodan parse -> file, no shell=True
            with open(parsed_file, 'w') as out_fh:
                parse_result = subprocess.run(
                    ['shodan', 'parse', '--fields', 'hostnames', raw_file],
                    stdout=out_fh,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=60
                )

            if parse_result.returncode != 0:
                logger.warning("Shodan parse error: %s", parse_result.stderr.strip())
                return []

            if not os.path.exists(parsed_file):
                return []

            with open(parsed_file, 'r') as f:
                raw_data = f.readlines()

            subdomains = set()

            for line in raw_data:
                if not line.strip():
                    continue

                parts = line.strip().split(';')

                for part in parts:
                    hostname = part.strip()
                    if hostname and _matches_domain(hostname, domain):
                        subdomains.add(hostname)

            return sorted(list(subdomains))

    except subprocess.TimeoutExpired:
        logger.warning("Shodan operation timeout")
        return []

    except FileNotFoundError:
        logger.warning("Shodan CLI not found in PATH")
        return []

    except Exception as e:
        logger.error("Shodan unexpected error: %s", e)
        return []
