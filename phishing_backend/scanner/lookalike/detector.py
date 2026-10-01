import re

from .indian_brands import INDIAN_BRANDS_CATALOG


def levenshtein_distance(s1: str, s2: str) -> int:
    """Computes the Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


def check_brand_impersonation(domain: str) -> dict:
    """
    Analyzes whether a given domain is impersonating an Indian brand.
    Returns:
        {
            "is_impersonation": bool,
            "brand_key": str | None,
            "brand_name": str | None,
            "reason": str | None,
            "severity": "high" | "critical" | "none"
        }
    """
    domain_lower = domain.lower().strip()

    # Split domain into base name (e.g. 'hdfc-secure-login' from 'hdfc-secure-login.xyz')
    domain_parts = domain_lower.split(".")
    if len(domain_parts) >= 2:
        domain_name = domain_parts[0]
        full_sld = ".".join(domain_parts[:-1])
    else:
        domain_name = domain_lower
        full_sld = domain_lower

    for brand_key, brand_info in INDIAN_BRANDS_CATALOG.items():
        brand_name = brand_info["name"]
        verified_domains = brand_info["domains"]

        # If it is a legitimate verified domain or subdomain of it, skip
        if any(domain_lower == vd or domain_lower.endswith("." + vd) for vd in verified_domains):
            continue

        # 1. Check keyword presence in domain name
        for keyword in brand_info["keywords"]:
            # Match word boundary or hyphenated keyword (e.g., 'hdfc-kyc', 'sbi_login', 'paytm-update')
            pattern = rf"(^|[-_.0-9]){re.escape(keyword)}([-_.0-9]|$)"
            if re.search(pattern, full_sld) or keyword in domain_name:
                return {
                    "is_impersonation": True,
                    "brand_key": brand_key,
                    "brand_name": brand_name,
                    "reason": f"Impersonating Indian financial institution or brand: {brand_name}.",
                    "severity": "high",
                }

        # 2. Check Typosquatting / Levenshtein edit distance on main brands
        for verified_domain in verified_domains:
            vd_base = verified_domain.split(".")[0]
            # If domain name is very close in edit distance (distance <= 2) and length >= 4
            if len(vd_base) >= 4 and len(domain_name) >= 4:
                dist = levenshtein_distance(domain_name, vd_base)
                if 1 <= dist <= 2 and abs(len(domain_name) - len(vd_base)) <= 2:
                    return {
                        "is_impersonation": True,
                        "brand_key": brand_key,
                        "brand_name": brand_name,
                        "reason": f"Typosquatting detected targeting {brand_name} (similar to {verified_domain}).",
                        "severity": "high",
                    }

    return {
        "is_impersonation": False,
        "brand_key": None,
        "brand_name": None,
        "reason": None,
        "severity": "none",
    }
