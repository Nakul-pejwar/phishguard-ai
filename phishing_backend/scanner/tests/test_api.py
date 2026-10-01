import pytest
from rest_framework import status
from rest_framework.test import APIClient

from scanner.models import URLScanResult


@pytest.fixture
def api_client():
    return APIClient()


@pytest.mark.django_db
def test_check_url_api_valid_url(api_client):
    response = api_client.post(
        "/api/check-url/",
        {"url": "https://github.com/login"},
        format="json",
    )
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["success"] is True
    assert "result" in data
    assert data["result"]["domain"] == "github.com"
    assert data["result"]["verdict"] in ["safe", "suspicious", "phishing"]
    assert data["result"]["risk_level"] in ["low", "medium", "high"]

    # Verify DB logging
    scan_log = URLScanResult.objects.first()
    assert scan_log is not None
    assert scan_log.domain == "github.com"
    assert scan_log.verdict == data["result"]["verdict"]


@pytest.mark.django_db
def test_check_url_api_empty_url(api_client):
    response = api_client.post(
        "/api/check-url/",
        {"url": ""},
        format="json",
    )
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    data = response.json()
    assert data["success"] is False
    assert "URL is required." in data["message"]


@pytest.mark.django_db
def test_check_url_api_missing_payload(api_client):
    response = api_client.post(
        "/api/check-url/",
        {},
        format="json",
    )
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    data = response.json()
    assert data["success"] is False


@pytest.mark.django_db
def test_check_url_api_huge_payload(api_client):
    huge_url = "https://example.com/" + ("a" * 5000)
    response = api_client.post(
        "/api/check-url/",
        {"url": huge_url},
        format="json",
    )
    # The API should handle large URLs gracefully without crashing
    assert response.status_code in [status.HTTP_200_OK, status.HTTP_400_BAD_REQUEST]


@pytest.mark.django_db
def test_check_url_api_insecure_sensitive_url(api_client):
    response = api_client.post(
        "/api/check-url/",
        {"url": "http://fake-banking-login-portal.net/verify-account"},
        format="json",
    )
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["success"] is True
    assert data["result"]["phishing_probability"] > 0
    assert len(data["result"]["reasons"]) >= 1
