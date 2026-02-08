import requests

import config
from logger import logger


def get_securitytrails_subdomains(domain):
    """
    Fetch subdomains from SecurityTrails API.

    Args:
        domain: Target domain to enumerate

    Returns:
        List of full subdomains (subdomain.domain.com) or empty list on failure
    """
    api_key = config.API_KEYS.get('SECURITYTRAILS_API_KEY')
    if not api_key:
        logger.warning("SecurityTrails API key not configured — skipping")
        return []

    url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"

    headers = {
        'APIKEY': api_key,
        'Accept': 'application/json'
    }

    try:
        response = requests.get(url, headers=headers, timeout=30)

        if response.status_code == 200:
            data = response.json()
            subdomains = data.get('subdomains', [])

            full_subdomains = []
            for subdomain in subdomains:
                if subdomain:
                    full_subdomain = f"{subdomain}.{domain}"
                    full_subdomains.append(full_subdomain)

            return full_subdomains

        elif response.status_code == 429:
            logger.warning("SecurityTrails rate limit reached")
            return []

        elif response.status_code == 401:
            logger.warning("SecurityTrails API key invalid")
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
