import requests
import os

import config
from logger import logger


def _matches_domain(hostname, domain):
    """Proper suffix-based domain matching."""
    return hostname == domain or hostname.endswith('.' + domain)


def get_urlscan_subdomains(domain):
    """
    Fetch subdomains from URLScan.io Search API.
    Also saves all URLs to a separate file for further analysis/crawling.

    Args:
        domain: Target domain to enumerate

    Returns:
        List of unique subdomains or empty list on failure
    """
    api_key = config.API_KEYS.get('URLSCAN_API_KEY')
    if not api_key:
        logger.warning("URLScan.io API key not configured — skipping")
        return []

    url = "https://urlscan.io/api/v1/search/"

    headers = {
        'API-Key': api_key,
        'Accept': 'application/json'
    }

    params = {
        'q': f'domain:{domain}',
        'size': 10000
    }

    try:
        response = requests.get(url, headers=headers, params=params, timeout=60)

        if response.status_code == 200:
            data = response.json()

            subdomains = set()
            urls = set()

            results = data.get('results', [])

            for result in results:
                page = result.get('page', {})
                subdomain = page.get('domain', '')
                page_url = page.get('url', '')

                task = result.get('task', {})
                if not subdomain:
                    subdomain = task.get('domain', '')
                if not page_url:
                    page_url = task.get('url', '')

                if subdomain and _matches_domain(subdomain, domain):
                    subdomains.add(subdomain)

                if page_url and domain in page_url:
                    urls.add(page_url)

            if urls:
                urlscan_dir = os.path.join(os.getcwd(), 'output', 'urlscan_results', domain)
                if not os.path.exists(urlscan_dir):
                    os.makedirs(urlscan_dir)

                urls_file = os.path.join(urlscan_dir, 'urls.txt')
                with open(urls_file, 'w') as f:
                    for url_item in sorted(urls):
                        f.write(f"{url_item}\n")

                logger.info("URLScan.io URLs saved to: %s", urls_file)

            total_scans = data.get('total', 0)
            logger.info("URLScan.io: Found %d scan results", total_scans)
            logger.info("URLScan.io: Extracted %d unique URLs", len(urls))

            return sorted(list(subdomains))

        elif response.status_code == 401:
            logger.warning("URLScan.io API key invalid or unauthorized")
            return []

        elif response.status_code == 429:
            logger.warning("URLScan.io rate limit reached")
            return []

        else:
            logger.warning("URLScan.io API error: HTTP %d", response.status_code)
            return []

    except requests.exceptions.Timeout:
        logger.warning("URLScan.io request timeout")
        return []

    except requests.exceptions.RequestException as e:
        logger.warning("URLScan.io request error: %s", e)
        return []

    except Exception as e:
        logger.error("URLScan.io unexpected error: %s", e)
        return []
