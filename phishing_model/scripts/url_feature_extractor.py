from urllib.parse import urlparse
import re


def normalize_url(url: str) -> str:
    url = url.strip()

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    return url


def is_ip_address(domain: str) -> int:
    pattern = r"^\d{1,3}(\.\d{1,3}){3}$"
    return 1 if re.match(pattern, domain) else 0


def get_tld(domain: str) -> str:
    parts = domain.split(".")
    if len(parts) > 1:
        return parts[-1].lower()
    return ""


def count_obfuscated_chars(url: str) -> int:
    return len(re.findall(r"%[0-9a-fA-F]{2}", url))


def extract_url_features(url: str) -> dict:
    url = normalize_url(url)
    parsed = urlparse(url)

    domain = parsed.netloc.lower()

    if "@" in domain:
        domain = domain.split("@")[-1]

    if ":" in domain:
        domain = domain.split(":")[0]

    if domain.startswith("www."):
        domain = domain[4:]

    tld = get_tld(domain)

    url_length = len(url)
    domain_length = len(domain)

    letters = sum(c.isalpha() for c in url)
    digits = sum(c.isdigit() for c in url)

    equals_count = url.count("=")
    qmark_count = url.count("?")
    ampersand_count = url.count("&")

    special_count = sum(not c.isalnum() for c in url)

    obfuscated_count = count_obfuscated_chars(url)

    domain_parts = domain.split(".")
    no_of_subdomains = max(len(domain_parts) - 2, 0)

    return {
        "URLLength": url_length,
        "DomainLength": domain_length,
        "IsDomainIP": is_ip_address(domain),
        "TLDLength": len(tld),
        "NoOfSubDomain": no_of_subdomains,
        "HasObfuscation": 1 if obfuscated_count > 0 else 0,
        "NoOfObfuscatedChar": obfuscated_count,
        "ObfuscationRatio": obfuscated_count / url_length if url_length else 0,
        "NoOfLettersInURL": letters,
        "LetterRatioInURL": letters / url_length if url_length else 0,
        "NoOfDegitsInURL": digits,
        "DegitRatioInURL": digits / url_length if url_length else 0,
        "NoOfEqualsInURL": equals_count,
        "NoOfQMarkInURL": qmark_count,
        "NoOfAmpersandInURL": ampersand_count,
        "NoOfOtherSpecialCharsInURL": special_count,
        "SpacialCharRatioInURL": special_count / url_length if url_length else 0,
        "IsHTTPS": 1 if parsed.scheme == "https" else 0,
    }