import pytest

from scanner.ml.predictor import get_domain, normalize_url


@pytest.mark.parametrize(
    "input_url, expected_url",
    [
        ("google.com", "https://google.com"),
        ("HTTP://EXAMPLE.COM/Path?q=1", "http://example.com/path?q=1"),
        ("https://www.github.com/login", "https://github.com/login"),
        ("http://user:pass@evil.com:8080/page", "http://evil.com/page"),
        ("https://WWW.Sub.Domain.com/test", "https://sub.domain.com/test"),
        ("https://bank.com/login#fragment", "https://bank.com/login"),
    ],
)
def test_normalize_url(input_url, expected_url):
    assert normalize_url(input_url) == expected_url


@pytest.mark.parametrize(
    "clean_url, expected_domain",
    [
        ("https://google.com/search", "google.com"),
        ("http://sub.evil-phish.xyz/login", "sub.evil-phish.xyz"),
        ("https://github.com", "github.com"),
    ],
)
def test_get_domain(clean_url, expected_domain):
    assert get_domain(clean_url) == expected_domain
