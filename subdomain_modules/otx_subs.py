import requests

import config
from logger import logger


def _matches_domain(hostname, domain):
    """Proper suffix-based domain matching."""
    return hostname == domain or hostname.endswith('.' + domain)


def get_otx_subdomains(domain):
    """
    Fetch subdomains from AlienVault OTX (Open Threat Exchange).
    Uses Passive DNS data to extract subdomains.

    Args:
        domain: Target domain to enumerate

    Returns:
        List of unique subdomains or empty list on failure
    """
    api_key = config.API_KEYS.get('OTX_API_KEY')
    if not api_key:
        logger.warning("AlienVault OTX API key not configured — skipping")
        return []

    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"

    headers = {
        'X-OTX-API-KEY': api_key,
        'Accept': 'application/json'
    }

    try:
        response = requests.get(url, headers=headers, timeout=60)

        if response.status_code == 200:
            data = response.json()

            subdomains = set()
            passive_dns = data.get('passive_dns', [])

            for record in passive_dns:
                hostname = record.get('hostname', '')

                if hostname and _matches_domain(hostname, domain) and hostname != domain:
                    subdomains.add(hostname)

            return sorted(list(subdomains))

        elif response.status_code == 401:
            logger.warning("AlienVault OTX API key invalid or unauthorized")
            return []

        elif response.status_code == 404:
            logger.debug("No AlienVault OTX data found for %s", domain)
            return []

        elif response.status_code == 429:
            logger.warning("AlienVault OTX rate limit reached")
            return []

        else:
            logger.warning("AlienVault OTX API error: HTTP %d", response.status_code)
            return []

    except requests.exceptions.Timeout:
        logger.warning("AlienVault OTX request timeout")
        return []

    except requests.exceptions.RequestException as e:
        logger.warning("AlienVault OTX request error: %s", e)
        return []

    except Exception as e:
        logger.error("AlienVault OTX unexpected error: %s", e)
        return []
