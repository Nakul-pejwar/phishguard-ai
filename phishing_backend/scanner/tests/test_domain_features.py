from scanner.features.domain_features import (
    calculate_entropy,
    extract_domain_features,
    is_ip_in_url,
    is_punycode_or_homoglyph,
)


def test_entropy_calculation():
    assert calculate_entropy("") == 0.0
    assert calculate_entropy("aaaaaa") == 0.0
    # High entropy randomized string
    assert calculate_entropy("a8f9b2c3d4e5f6") > 3.0


def test_is_ip_in_url():
    assert is_ip_in_url("192.168.1.1") is True
    assert is_ip_in_url("10.0.0.1:8080") is True
    assert is_ip_in_url("google.com") is False
    assert is_ip_in_url("my-domain.net") is False


def test_is_punycode_or_homoglyph():
    assert is_punycode_or_homoglyph("xn--gogle-pua.com") is True
    assert is_punycode_or_homoglyph("google.com") is False
    assert is_punycode_or_homoglyph("hdfcbank.com") is False


def test_extract_domain_features_flags_risky_elements():
    features = extract_domain_features("http://192.168.1.1/login", "192.168.1.1")
    assert features["has_ip"] is True
    assert features["risk_points"] > 0
    assert any("IP address" in r for r in features["reasons"])

    tld_features = extract_domain_features("http://verify-bank.account.security.service.top/login", "verify-bank.account.security.service.top")
    assert tld_features["has_risky_tld"] is True
    assert tld_features["subdomain_depth"] >= 3
    assert tld_features["risk_points"] >= 30
