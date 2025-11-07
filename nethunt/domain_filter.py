"""
Domain filtering and classification
"""

from urllib.parse import urlparse

# Whitelist of known legitimate domains
LEGITIMATE_DOMAINS = {
    # Microsoft
    "microsoft.com", "windowsupdate.com", "msftconnecttest.com",
    "live.com", "bing.com", "msn.com", "office.com",
    "microsoftonline.com", "windows.com", "skype.com",
    "onedrive.com", "sharepoint.com", "azure.com",

    # Google
    "google.com", "googleapis.com", "gstatic.com",
    "googleusercontent.com", "youtube.com",
    "android.com", "chrome.com",

    # Mozilla
    "mozilla.org", "mozilla.com", "firefox.com",

    # Certificate Authorities (CRL/OCSP)
    "digicert.com", "verisign.com", "globalsign.com",
    "sectigo.com", "trust-provider.com", "usertrust.com",
    "letsencrypt.org", "comodo.com",

    # CDNs
    "cloudflare.com", "akamai.com", "fastly.com",
    "cloudfront.net", "azureedge.net",

    # Adobe
    "adobe.com", "adobe.io",

    # Apple
    "apple.com", "icloud.com", "itunes.com",

    # Other common
    "dropbox.com", "amazon.com", "amazonaws.com"
}


def is_legitimate_domain(domain: str) -> bool:
    """
    Check if a domain is in the whitelist of legitimate domains

    Args:
        domain: Domain name (can be subdomain like api.microsoft.com)

    Returns:
        True if domain is whitelisted, False otherwise
    """
    if not domain:
        return False

    # Remove port if present
    if ":" in domain:
        domain = domain.split(":")[0]

    domain = domain.lower().strip()

    # Check exact match
    if domain in LEGITIMATE_DOMAINS:
        return True

    # Check if it's a subdomain of a whitelisted domain
    for legit_domain in LEGITIMATE_DOMAINS:
        if domain.endswith("." + legit_domain):
            return True

    return False


def classify_url(url: str) -> str:
    """
    Classify a URL as legitimate, suspicious, or malicious

    Returns:
        "legitimate", "suspicious", or "malicious"
    """
    try:
        parsed = urlparse(url)
        domain = parsed.netloc

        if is_legitimate_domain(domain):
            return "legitimate"

        # Check for suspicious indicators
        suspicious_indicators = [
            "microsoft" in domain.lower() and not is_legitimate_domain(domain),
            "windows" in domain.lower() and not is_legitimate_domain(domain),
            "google" in domain.lower() and not is_legitimate_domain(domain),
            "update" in domain.lower() and not is_legitimate_domain(domain),
            ".live" in domain and not is_legitimate_domain(domain),
            "trycloudflare.com" in domain,  # Free CloudFlare tunnels often used by malware
        ]

        if any(suspicious_indicators):
            return "malicious"

        return "suspicious"
    except:
        return "suspicious"


def filter_legitimate_traffic(requests: list, filter_level: str = "all") -> list:
    """
    Filter out legitimate traffic from requests

    Args:
        requests: List of HTTP request dictionaries with 'url' field
        filter_level: "all" (remove all legitimate), "none" (keep all), "suspicious_only" (remove only clearly suspicious)

    Returns:
        Filtered list of requests
    """
    if filter_level == "none":
        return requests

    filtered = []
    for req in requests:
        url = req.get("url", "")
        classification = classify_url(url)

        if filter_level == "all":
            # Remove all legitimate traffic
            if classification != "legitimate":
                filtered.append(req)
        elif filter_level == "suspicious_only":
            # Only keep malicious and suspicious
            if classification in ["malicious", "suspicious"]:
                filtered.append(req)

    return filtered
