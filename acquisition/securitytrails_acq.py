import requests

import config
from logger import logger


def get_securitytrails_associated(domain):
    """
    Fetch associated domains from SecurityTrails API.
    Returns domains that share infrastructure/registrant details with the target.

    Args:
        domain: Target domain to find associated domains for

    Returns:
        List of associated domain names or empty list on failure
    """
    api_key = config.API_KEYS.get('SECURITYTRAILS_API_KEY')
    if not api_key:
        logger.warning("SecurityTrails API key not configured — skipping acquisition")
        return []

    url = f"https://api.securitytrails.com/v1/domain/{domain}/associated"

    headers = {
        'APIKEY': api_key,
        'Accept': 'application/json'
    }

    try:
        response = requests.get(url, headers=headers, timeout=60)

        if response.status_code == 200:
            data = response.json()

            associated_domains = set()
            records = data.get('records', [])

            for record in records:
                hostname = record.get('hostname', '')
                if hostname and hostname != domain:
                    associated_domains.add(hostname)

            return sorted(list(associated_domains))

        elif response.status_code == 401:
            logger.warning("SecurityTrails API key invalid or unauthorized")
            return []

        elif response.status_code == 404:
            logger.debug("No SecurityTrails associated data found for %s", domain)
            return []

        elif response.status_code == 429:
            logger.warning("SecurityTrails rate limit reached")
            return []

        else:
            logger.warning("SecurityTrails API error: HTTP %d", response.status_code)
            return []

    except requests.exceptions.Timeout:
        logger.warning("SecurityTrails request timeout")
        return []

    except requests.exceptions.RequestException as e:
        logger.warning("SecurityTrails request error: %s", e)
        return []

    except Exception as e:
        logger.error("SecurityTrails unexpected error: %s", e)
        return []
