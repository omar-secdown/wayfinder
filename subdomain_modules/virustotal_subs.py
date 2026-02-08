import requests
import time

import config
from logger import logger


def get_virustotal_subdomains(domain):
    """
    Fetch subdomains from VirusTotal v3 API.

    Args:
        domain: Target domain to enumerate

    Returns:
        List of subdomains or empty list on failure
    """
    api_key = config.API_KEYS.get('VIRUSTOTAL_API_KEY')
    if not api_key:
        logger.warning("VirusTotal API key not configured — skipping")
        return []

    headers = {
        'x-apikey': api_key,
        'Accept': 'application/json',
    }

    all_subdomains = []
    url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains"
    params = {'limit': 40}

    try:
        while url:
            response = requests.get(url, headers=headers, params=params, timeout=30)

            if response.status_code == 429:
                logger.warning("VirusTotal rate limit reached, waiting 60 seconds...")
                time.sleep(60)
                response = requests.get(url, headers=headers, params=params, timeout=30)

            if response.status_code != 200:
                logger.warning("VirusTotal API error: HTTP %d", response.status_code)
                break

            data = response.json()

            for item in data.get('data', []):
                subdomain_id = item.get('id', '').strip()
                if subdomain_id:
                    all_subdomains.append(subdomain_id)

            # Cursor-based pagination
            cursor = data.get('meta', {}).get('cursor')
            if cursor and data.get('data'):
                params = {'limit': 40, 'cursor': cursor}
            else:
                url = None

        return all_subdomains

    except requests.exceptions.Timeout:
        logger.warning("VirusTotal request timeout")
        return all_subdomains

    except requests.exceptions.RequestException as e:
        logger.warning("VirusTotal request error: %s", e)
        return all_subdomains

    except Exception as e:
        logger.error("VirusTotal unexpected error: %s", e)
        return all_subdomains
