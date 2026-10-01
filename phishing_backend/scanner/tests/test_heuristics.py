import pytest

from scanner.ml.predictor import (
    contains_sensitive_keyword,
    is_trusted_domain,
    predict_phishing_url,
)


def test_is_trusted_domain():
    assert is_trusted_domain("google.com") is True
    assert is_trusted_domain("sub.google.com") is True
    assert is_trusted_domain("github.com") is True
    assert is_trusted_domain("docs.github.com") is True
    assert is_trusted_domain("attacker-google.com") is False
    assert is_trusted_domain("evil-phish.xyz") is False


def test_contains_sensitive_keyword():
    assert contains_sensitive_keyword("https://safe.com/login") is True
    assert contains_sensitive_keyword("https://safe.com/verify-otp") is True
    assert contains_sensitive_keyword("https://bank.com/account/password") is True
    assert contains_sensitive_keyword("https://news.com/articles/today") is False


def test_trusted_domain_caps_risk():
    result = predict_phishing_url("https://google.com/login")
    assert result["domain"] == "google.com"
    assert result["phishing_probability"] <= 20
    assert result["verdict"] == "safe"
    assert "Trusted domain detected, risk reduced." in result["reasons"]


def test_insecure_http_increases_risk():
    result = predict_phishing_url("http://example-unknown-site.org/page")
    assert "URL does not use HTTPS." in result["reasons"]


def test_sensitive_keyword_increases_risk():
    result = predict_phishing_url("https://unknown-domain-payment.net/secure-login-verify")
    assert "Sensitive keyword found in URL." in result["reasons"]


@pytest.mark.parametrize(
    "url, expected_verdict, expected_risk",
    [
        ("https://github.com/login", "safe", "low"),
        ("https://wikipedia.org", "safe", "low"),
    ],
)
def test_verdict_thresholds(url, expected_verdict, expected_risk):
    result = predict_phishing_url(url)
    assert result["verdict"] == expected_verdict
    assert result["risk_level"] == expected_risk
    assert 0 <= result["phishing_probability"] <= 100
    assert 0 <= result["legitimate_probability"] <= 100
    assert round(result["phishing_probability"] + result["legitimate_probability"], 1) == 100.0
