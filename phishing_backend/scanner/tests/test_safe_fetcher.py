import pytest

from scanner.features.safe_fetcher import (
    SSRFSecurityError,
    is_ip_allowed,
    safe_unshorten_url,
    validate_url_for_ssrf,
)


@pytest.mark.parametrize(
    "restricted_ip",
    [
        "127.0.0.1",
        "127.0.0.2",
        "10.0.0.1",
        "10.255.255.254",
        "172.16.0.1",
        "172.31.255.255",
        "192.168.1.1",
        "192.168.0.254",
        "169.254.169.254",  # AWS instance metadata
        "0.0.0.0",
        "224.0.0.1",
        "::1",
    ],
)
def test_blocked_restricted_ips(restricted_ip):
    assert is_ip_allowed(restricted_ip) is False


@pytest.mark.parametrize(
    "public_ip",
    [
        "8.8.8.8",
        "1.1.1.1",
        "142.250.190.46",
        "140.82.121.4",
    ],
)
def test_allowed_public_ips(public_ip):
    assert is_ip_allowed(public_ip) is True


@pytest.mark.parametrize(
    "ssrf_target_url",
    [
        "http://127.0.0.1:8000/admin",
        "http://localhost:8000/api",
        "http://169.254.169.254/latest/meta-data/",
        "http://10.0.0.5/internal/dashboard",
        "http://192.168.1.1/router",
        "file:///etc/passwd",
        "ftp://127.0.0.1",
    ],
)
def test_validate_url_blocks_ssrf(ssrf_target_url):
    with pytest.raises(SSRFSecurityError):
        validate_url_for_ssrf(ssrf_target_url)


def test_safe_unshorten_url_returns_gracefully_on_invalid_or_ssrf():
    # Attempting to unshorten an SSRF target should not crash and should reject
    res = safe_unshorten_url("http://127.0.0.1:8000/redirect")
    assert res == "http://127.0.0.1:8000/redirect"
