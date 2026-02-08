import requests

import config
from logger import logger


def get_chaos_subdomains(domain):
    """
    Fetch subdomains from ProjectDiscovery Chaos.
    Chaos provides subdomain data from bug bounty programs.

    Args:
        domain: Target domain to enumerate

    Returns:
        List of unique subdomains or empty list on failure
    """
    api_key = config.API_KEYS.get('CHAOS_API_KEY')
    if not api_key:
        logger.warning("Chaos API key not configured — skipping")
        return []

    url = f"https://dns.projectdiscovery.io/dns/{domain}/subdomains"

    headers = {
        'Authorization': api_key,
        'Accept': 'application/json'
    }

    try:
        response = requests.get(url, headers=headers, timeout=30)

        if response.status_code == 200:
            data = response.json()
            subdomains = data.get('subdomains', [])

            full_subdomains = []
            for subdomain in subdomains:
                if not subdomain or subdomain in ['', '*', '*.']:
                    continue

                if subdomain.startswith('*.'):
                    subdomain = subdomain[2:]

                if not subdomain:
                    continue

                full_subdomain = f"{subdomain}.{domain}"
                full_subdomains.append(full_subdomain)

            return full_subdomains

        elif response.status_code == 401:
            logger.warning("Chaos API key invalid or unauthorized")
            return []

        elif response.status_code == 404:
            logger.debug("No Chaos data found for %s", domain)
            return []

        elif response.status_code == 429:
            logger.warning("Chaos rate limit reached")
            return []

        else:
            logger.warning("Chaos API error: HTTP %d", response.status_code)
            return []

    except requests.exceptions.Timeout:
        logger.warning("Chaos request timeout")
        return []

    except requests.exceptions.RequestException as e:
        logger.warning("Chaos request error: %s", e)
        return []

    except Exception as e:
        logger.error("Chaos unexpected error: %s", e)
        return []
