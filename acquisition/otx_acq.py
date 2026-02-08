import requests

import config
from logger import logger


def get_otx_associated(domain, email_filters=None):
    """
    Fetch related domains from AlienVault OTX WHOIS data.
    Filters results based on registrant email domain names.

    Args:
        domain: Target domain to find associated domains for
        email_filters: List of email domain names to filter by (without TLD)
                      e.g., ['abbvie', 'caterpillar', 'abbfe']
                      If None, defaults to filtering by target domain only

    Returns:
        List of associated domain names or empty list on failure
    """
    api_key = config.API_KEYS.get('OTX_API_KEY')
    if not api_key:
        logger.warning("AlienVault OTX API key not configured — skipping acquisition")
        return []

    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/whois"

    headers = {
        'X-OTX-API-KEY': api_key,
        'Accept': 'application/json'
    }

    if email_filters is None:
        domain_parts = domain.lower().split('.')
        if len(domain_parts) >= 2:
            email_filters = [domain_parts[0]]
        else:
            email_filters = []

    email_filters = [f.lower().strip() for f in email_filters if f.strip()]

    if not email_filters:
        logger.warning("No valid email filters provided")
        return []

    try:
        response = requests.get(url, headers=headers, timeout=60)

        if response.status_code == 200:
            data = response.json()

            related_domains = set()
            related_records = data.get('related', [])

            for record in related_records:
                if record.get('related_type') == 'email':
                    related_domain_name = record.get('domain', '')
                    email = record.get('related', '').lower()

                    if email and '@' in email:
                        if any(filter_word in email for filter_word in email_filters):
                            if related_domain_name and related_domain_name.lower() != domain.lower():
                                related_domains.add(related_domain_name)

            return sorted(list(related_domains))

        elif response.status_code == 401:
            logger.warning("AlienVault OTX API key invalid or unauthorized")
            return []

        elif response.status_code == 404:
            logger.debug("No AlienVault OTX WHOIS data found for %s", domain)
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
