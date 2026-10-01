import math
import re
from urllib.parse import urlparse

RISKY_TLDS = {
    "xyz",
    "top",
    "tk",
    "ml",
    "ga",
    "cf",
    "gq",
    "icu",
    "buzz",
    "fit",
    "rest",
    "work",
    "click",
    "live",
    "monster",
    "surf",
    "cam",
    "kim",
    "quest",
    "country",
}

SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "is.gd",
    "buff.ly",
    "ow.ly",
    "goo.gl",
    "rebrand.ly",
    "cutt.ly",
    "shorturl.at",
}


def calculate_entropy(text: str) -> float:
    """Computes Shannon entropy of a string (higher value = more randomized/obfuscated)."""
    if not text:
        return 0.0
    length = len(text)
    freq = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 3)


def is_ip_in_url(domain: str) -> bool:
    """Checks if the domain is an IPv4 or hexadecimal IP address."""
    ipv4_pattern = r"^(\d{1,3}\.){3}\d{1,3}(:\d+)?$"
    if re.match(ipv4_pattern, domain):
        return True
    hex_pattern = r"^0x[0-9a-fA-F]+(\.0x[0-9a-fA-F]+)*$"
    return bool(re.match(hex_pattern, domain))


def is_punycode_or_homoglyph(domain: str) -> bool:
    """Detects IDN Punycode domains or mixed-script homoglyphs."""
    if "xn--" in domain.lower():
        return True
    # Detect non-ASCII unicode characters in domain
    try:
        domain.encode("ascii")
        return False
    except UnicodeEncodeError:
        return True


def extract_domain_features(url: str, domain: str) -> dict:
    parsed = urlparse(url)
    domain_clean = domain.lower()
    tld = domain_clean.split(".")[-1] if "." in domain_clean else ""

    subdomain_parts = domain_clean.split(".")
    subdomain_depth = max(0, len(subdomain_parts) - 2)

    has_ip = is_ip_in_url(domain_clean)
    has_risky_tld = tld in RISKY_TLDS
    has_punycode = is_punycode_or_homoglyph(domain_clean)
    is_shortener = domain_clean in SHORTENER_DOMAINS or any(domain_clean.endswith("." + s) for s in SHORTENER_DOMAINS)

    domain_entropy = calculate_entropy(domain_clean)
    path_entropy = calculate_entropy(parsed.path)

    hyphen_count = domain_clean.count("-")
    at_symbol_count = url.count("@")
    double_slash_in_path = "//" in parsed.path

    reasons = []
    risk_points = 0

    if has_ip:
        risk_points += 35
        reasons.append("IP address used as domain instead of hostname.")

    if has_punycode:
        risk_points += 30
        reasons.append("Punycode / IDN homoglyph character set detected.")

    if has_risky_tld:
        risk_points += 20
        reasons.append(f"High-risk Top Level Domain (. {tld}) associated with phishing campaigns.")

    if subdomain_depth >= 3:
        risk_points += 15
        reasons.append(f"Excessive subdomain nesting ({subdomain_depth} levels).")

    if hyphen_count >= 3:
        risk_points += 15
        reasons.append(f"Excessive hyphens in domain ({hyphen_count} hyphens).")

    if domain_entropy > 4.2:
        risk_points += 15
        reasons.append(f"High domain randomness / entropy ({domain_entropy}).")

    if at_symbol_count > 0:
        risk_points += 25
        reasons.append("Embedded credentials (@ symbol) found in URL.")

    if double_slash_in_path:
        risk_points += 15
        reasons.append("Double slash redirection detected in path.")

    if is_shortener:
        reasons.append("URL shortening service detected.")

    return {
        "domain_entropy": domain_entropy,
        "path_entropy": path_entropy,
        "subdomain_depth": subdomain_depth,
        "has_ip": has_ip,
        "has_risky_tld": has_risky_tld,
        "has_punycode": has_punycode,
        "is_shortener": is_shortener,
        "hyphen_count": hyphen_count,
        "risk_points": risk_points,
        "reasons": reasons,
    }
