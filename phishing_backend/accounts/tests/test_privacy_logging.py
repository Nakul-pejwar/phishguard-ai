import hashlib

import pytest
from rest_framework import status
from rest_framework.test import APIClient

from accounts.models import UsageLog


@pytest.fixture
def api_client():
    return APIClient()


@pytest.mark.django_db
def test_privacy_compliant_url_hashing(api_client):
    sensitive_token_url = "https://banking-portal.example.com/reset-password?token=secret_auth_token_98765&email=ceo@victim.com"
    response = api_client.post(
        "/api/check-url/",
        {"url": sensitive_token_url},
        format="json",
    )
    assert response.status_code == status.HTTP_200_OK

    # Check UsageLog
    log = UsageLog.objects.latest("id")
    assert log.domain == "banking-portal.example.com"
    # Verify the secret query token is NOT stored in plain text in the domain or hash fields
    assert "secret_auth_token_98765" not in log.domain
    assert "secret_auth_token_98765" not in log.url_hash

    # Verify that url_hash equals the sha256 hash of the normalized clean_url
    expected_hash = hashlib.sha256("https://banking-portal.example.com/reset-password?token=secret_auth_token_98765&email=ceo@victim.com".encode("utf-8")).hexdigest()
    assert log.url_hash == expected_hash
