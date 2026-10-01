import pytest
from rest_framework import status
from rest_framework.test import APIClient

from accounts.models import APIKey


@pytest.fixture
def api_client():
    return APIClient()


@pytest.fixture
def registered_user(api_client):
    res = api_client.post(
        "/api/auth/register/",
        {"email": "apikeyuser@example.com", "password": "Password123!"},
        format="json",
    )
    return res.json()


@pytest.mark.django_db
def test_create_and_list_api_keys(api_client, registered_user):
    token = registered_user["tokens"]["access"]
    api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")

    # Create API key
    res = api_client.post("/api/auth/api-keys/", {"name": "CI Scanner"}, format="json")
    assert res.status_code == status.HTTP_201_CREATED
    data = res.json()
    assert data["success"] is True
    assert "raw_key" in data
    assert data["raw_key"].startswith("pg_")
    assert data["api_key"]["name"] == "CI Scanner"

    # Verify key is stored hashed
    db_key = APIKey.objects.get(id=data["api_key"]["id"])
    assert db_key.hashed_key != data["raw_key"]
    assert db_key.verify_key(data["raw_key"]) is True

    # List API keys
    list_res = api_client.get("/api/auth/api-keys/")
    assert list_res.status_code == status.HTTP_200_OK
    keys = list_res.json()["api_keys"]
    assert len(keys) == 1
    assert "raw_key" not in keys[0]
    assert keys[0]["prefix"] == data["raw_key"][:8]


@pytest.mark.django_db
def test_scan_with_api_key(api_client, registered_user):
    token = registered_user["tokens"]["access"]
    api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")

    create_res = api_client.post("/api/auth/api-keys/", {"name": "CLI Key"}, format="json")
    raw_key = create_res.json()["raw_key"]

    # Clear Bearer credentials
    api_client.credentials()

    # Call /api/check-url/ using X-API-Key header
    api_client.credentials(HTTP_X_API_KEY=raw_key)
    scan_res = api_client.post("/api/check-url/", {"url": "https://github.com"}, format="json")
    assert scan_res.status_code == status.HTTP_200_OK
    assert scan_res.json()["success"] is True


@pytest.mark.django_db
def test_revoke_api_key(api_client, registered_user):
    token = registered_user["tokens"]["access"]
    api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")

    create_res = api_client.post("/api/auth/api-keys/", {"name": "Revocable Key"}, format="json")
    raw_key = create_res.json()["raw_key"]
    key_id = create_res.json()["api_key"]["id"]

    # Revoke key
    revoke_res = api_client.post(f"/api/auth/api-keys/{key_id}/revoke/")
    assert revoke_res.status_code == status.HTTP_200_OK

    # Try calling API with revoked key
    api_client.credentials()
    api_client.credentials(HTTP_X_API_KEY=raw_key)
    scan_res = api_client.post("/api/check-url/", {"url": "https://github.com"}, format="json")
    assert scan_res.status_code == status.HTTP_401_UNAUTHORIZED
