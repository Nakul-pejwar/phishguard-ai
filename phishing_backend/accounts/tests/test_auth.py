import pytest
from django.contrib.auth.models import User
from rest_framework import status
from rest_framework.test import APIClient

from accounts.models import Membership


@pytest.fixture
def api_client():
    return APIClient()


@pytest.mark.django_db
def test_user_registration_success(api_client):
    payload = {
        "email": "testuser@example.com",
        "password": "SuperSecretPassword123!",
        "org_name": "Acme Security",
    }
    response = api_client.post("/api/auth/register/", payload, format="json")
    assert response.status_code == status.HTTP_201_CREATED
    data = response.json()
    assert data["success"] is True
    assert "tokens" in data
    assert "access" in data["tokens"]
    assert "refresh" in data["tokens"]
    assert data["user"]["email"] == "testuser@example.com"
    assert data["organization"]["name"] == "Acme Security"

    # Verify database objects
    user = User.objects.get(email="testuser@example.com")
    membership = Membership.objects.get(user=user)
    assert membership.role == Membership.ROLE_OWNER
    assert membership.organization.name == "Acme Security"
    assert membership.organization.subscription.plan.slug == "free"


@pytest.mark.django_db
def test_user_registration_duplicate_email(api_client):
    User.objects.create_user(username="existing@example.com", email="existing@example.com", password="pass")
    payload = {
        "email": "existing@example.com",
        "password": "SuperSecretPassword123!",
    }
    response = api_client.post("/api/auth/register/", payload, format="json")
    assert response.status_code == status.HTTP_400_BAD_REQUEST


@pytest.mark.django_db
def test_user_login_success(api_client):
    # Register first
    reg_payload = {
        "email": "loginuser@example.com",
        "password": "LoginPassword123!",
    }
    api_client.post("/api/auth/register/", reg_payload, format="json")

    # Login
    login_payload = {
        "email": "loginuser@example.com",
        "password": "LoginPassword123!",
    }
    response = api_client.post("/api/auth/login/", login_payload, format="json")
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["success"] is True
    assert "tokens" in data
    assert data["user"]["email"] == "loginuser@example.com"


@pytest.mark.django_db
def test_user_login_invalid_credentials(api_client):
    response = api_client.post(
        "/api/auth/login/",
        {"email": "nobody@example.com", "password": "wrongpassword"},
        format="json",
    )
    assert response.status_code == status.HTTP_400_BAD_REQUEST


@pytest.mark.django_db
def test_token_refresh(api_client):
    reg_resp = api_client.post(
        "/api/auth/register/",
        {"email": "refresh@example.com", "password": "Password12345!"},
        format="json",
    )
    refresh_token = reg_resp.json()["tokens"]["refresh"]

    refresh_resp = api_client.post(
        "/api/auth/token/refresh/",
        {"refresh": refresh_token},
        format="json",
    )
    assert refresh_resp.status_code == status.HTTP_200_OK
    assert "access" in refresh_resp.json()


@pytest.mark.django_db
def test_auth_me_endpoint(api_client):
    reg_resp = api_client.post(
        "/api/auth/register/",
        {"email": "me@example.com", "password": "Password12345!"},
        format="json",
    )
    access_token = reg_resp.json()["tokens"]["access"]

    api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {access_token}")
    me_resp = api_client.get("/api/auth/me/")
    assert me_resp.status_code == status.HTTP_200_OK
    data = me_resp.json()
    assert data["success"] is True
    assert data["user"]["email"] == "me@example.com"
    assert data["quota"]["plan"] == "free"
    assert data["quota"]["daily_limit"] == 20
    assert data["quota"]["used_today"] == 0
