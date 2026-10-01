import pytest

from scanner.lookalike.detector import check_brand_impersonation, levenshtein_distance


def test_levenshtein_distance():
    assert levenshtein_distance("hdfc", "hdfc") == 0
    assert levenshtein_distance("hdfc", "hdfcbank") == 4
    assert levenshtein_distance("paytm", "paytmm") == 1
    assert levenshtein_distance("zerodha", "zerodhaa") == 1


@pytest.mark.parametrize(
    "legit_domain",
    [
        "hdfcbank.com",
        "netbanking.hdfcbank.com",
        "onlinesbi.sbi",
        "retail.onlinesbi.sbi",
        "icicibank.com",
        "paytm.com",
        "phonepe.com",
        "incometax.gov.in",
        "irctc.co.in",
    ],
)
def test_legitimate_brands_not_flagged(legit_domain):
    res = check_brand_impersonation(legit_domain)
    assert res["is_impersonation"] is False


@pytest.mark.parametrize(
    "lookalike_domain, expected_brand_keyword",
    [
        ("hdfc-secure-login.xyz", "hdfc"),
        ("onlinesbi-pan-kyc.top", "sbi"),
        ("paytm-cashback-claim.icu", "paytm"),
        ("phonepe-rewards-portal.net", "phonepe"),
        ("incometax-refund-status.xyz", "incometax"),
        ("irctc-ticket-refund.com", "irctc"),
        ("hdfcbaank.com", "hdfc"),
    ],
)
def test_lookalike_brands_detected(lookalike_domain, expected_brand_keyword):
    res = check_brand_impersonation(lookalike_domain)
    assert res["is_impersonation"] is True
    assert res["brand_key"] == expected_brand_keyword
    assert "impersonat" in res["reason"].lower() or "typosquatting" in res["reason"].lower()
