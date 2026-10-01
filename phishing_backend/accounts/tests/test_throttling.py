import pytest
from rest_framework import status
from rest_framework.test import APIClient

from accounts.models import Organization, Plan, UsageLog


@pytest.fixture
def api_client():
    return APIClient()


@pytest.mark.django_db
def test_free_plan_throttle_limit(api_client):
    reg_res = api_client.post(
        "/api/auth/register/",
        {"email": "freetier@example.com", "password": "Password123!"},
        format="json",
    )
    token = reg_res.json()["tokens"]["access"]
    api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")

    org = Organization.objects.get(slug=reg_res.json()["organization"]["slug"])

    # Simulate 20 usage logs for today
    for i in range(20):
        UsageLog.objects.create(
            organization=org,
            domain="example.com",
            url_hash=f"hash_{i}",
            verdict="safe",
            risk_level="low",
        )

    # 21st request should be throttled
    response = api_client.post("/api/check-url/", {"url": "https://github.com"}, format="json")
    assert response.status_code == status.HTTP_429_TOO_MANY_REQUESTS
    data = response.json()
    assert data["success"] is False
    assert data["error"] == "rate_limit_exceeded"
    assert data["limit"] == 20
    assert data["used"] == 20
    assert data["plan"] == "free"


@pytest.mark.django_db
def test_anonymous_trial_throttle_limit(api_client):
    # Simulate 5 scans from client IP 192.0.2.1
    ip = "192.0.2.1"
    for i in range(5):
        UsageLog.objects.create(
            organization=None,
            domain="example.com",
            url_hash=f"anon_hash_{i}",
            verdict="safe",
            risk_level="low",
            ip_address=ip,
        )

    response = api_client.post(
        "/api/check-url/",
        {"url": "https://github.com"},
        format="json",
        REMOTE_ADDR=ip,
    )
    assert response.status_code == status.HTTP_429_TOO_MANY_REQUESTS
    data = response.json()
    assert data["success"] is False
    assert data["error"] == "trial_quota_exceeded"


@pytest.mark.django_db
def test_pro_plan_allows_higher_limits(api_client):
    reg_res = api_client.post(
        "/api/auth/register/",
        {"email": "protier@example.com", "password": "Password123!"},
        format="json",
    )
    token = reg_res.json()["tokens"]["access"]
    api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")

    org = Organization.objects.get(slug=reg_res.json()["organization"]["slug"])

    # Upgrade to Pro
    pro_plan, _ = Plan.objects.get_or_create(
        slug="pro",
        defaults={"name": "Pro", "daily_scan_limit": 1000, "price_inr": 499.00},
    )
    sub = org.subscription
    sub.plan = pro_plan
    sub.save()

    # Simulate 25 logs
    for i in range(25):
        UsageLog.objects.create(
            organization=org,
            domain="example.com",
            url_hash=f"pro_hash_{i}",
            verdict="safe",
            risk_level="low",
        )

    # 26th scan should succeed
    response = api_client.post("/api/check-url/", {"url": "https://github.com"}, format="json")
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["success"] is True
