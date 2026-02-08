import requests
import json
import time

from logger import logger


def _matches_domain(hostname, domain):
    """Proper suffix-based domain matching."""
    return hostname == domain or hostname.endswith('.' + domain)


def get_crtsh_subdomains(domain):
    """
    Fetch subdomains from crt.sh certificate transparency logs.

    Args:
        domain: Target domain to enumerate

    Returns:
        List of unique subdomains or empty list on failure
    """
    url = f"https://crt.sh/?dNSName=%25.{domain}&output=json"

    max_retries = 5
    retry_delay = 10

    for attempt in range(max_retries):
        try:
            response = requests.get(url, timeout=120)
            response.raise_for_status()

            try:
                data = response.json()
            except json.JSONDecodeError as e:
                logger.warning("crt.sh JSON decode error: %s", e)
                return []

            subdomains = set()

            for entry in data:
                if 'name_value' in entry:
                    raw_values = entry['name_value'].split("\n")

                    for raw_value in raw_values:
                        cleaned = raw_value.strip()

                        if cleaned.startswith('*.'):
                            cleaned = cleaned[2:]

                        if cleaned and _matches_domain(cleaned, domain):
                            subdomains.add(cleaned)

            return sorted(list(subdomains))

        except requests.exceptions.Timeout:
            logger.warning("crt.sh timeout (attempt %d/%d)", attempt + 1, max_retries)
            if attempt < max_retries - 1:
                logger.info("Retrying in %d seconds...", retry_delay)
                time.sleep(retry_delay)
                retry_delay *= 2
            else:
                logger.warning("Max retries reached for crt.sh")
                return []

        except requests.exceptions.HTTPError as e:
            logger.warning("crt.sh HTTP error: %s", e)
            if attempt < max_retries - 1 and e.response.status_code in [500, 502, 503, 504]:
                logger.info("Retrying in %d seconds...", retry_delay)
                time.sleep(retry_delay)
                retry_delay *= 2
            else:
                return []

        except requests.exceptions.RequestException as e:
            logger.warning("crt.sh request error: %s", e)
            if attempt < max_retries - 1:
                logger.info("Retrying in %d seconds...", retry_delay)
                time.sleep(retry_delay)
                retry_delay *= 2
            else:
                return []

        except Exception as e:
            logger.error("crt.sh unexpected error: %s", e)
            return []

    return []
