import pytest
from accounts.models import Membership, Organization, OrgPolicy, UsageLog
from django.contrib.auth.models import User
from rest_framework.test import APIClient


@pytest.mark.django_db
class TestBatchURLScannerAPI:
    def setup_method(self):
        self.client = APIClient()
        self.user = User.objects.create_user(
            username="batchtester", email="tester@example.com", password="password123"
        )
        self.org = Organization.objects.create(name="Batch Corp", slug="batch-corp")
        Membership.objects.create(
            organization=self.org, user=self.user, role="admin"
        )
        self.client.force_authenticate(user=self.user)

    def test_batch_scan_success(self):
        urls = [
            "https://www.google.com",
            "http://hdfc-kyc-update.xyz/login",
            "https://github.com",
        ]
        resp = self.client.post(
            "/api/check-urls/batch/",
            {"urls": urls, "sender_domain": "alerts@hdfcbank.com"},
            format="json",
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        assert data["count"] == 3
        assert len(data["results"]) == 3

        # Check that UsageLog entries were recorded
        logs = UsageLog.objects.filter(organization=self.org)
        assert logs.count() == 3

        # Lookalike with spoofed sender should be detected as phishing/threat
        hdfc_result = next(r for r in data["results"] if "hdfc" in r["clean_url"])
        assert hdfc_result["verdict"] in ["phishing", "suspicious"]
        assert hdfc_result["signals"]["sender_domain_mismatch"] is True

    def test_batch_scan_empty_urls_validation(self):
        resp = self.client.post("/api/check-urls/batch/", {"urls": []}, format="json")
        assert resp.status_code == 400
        assert "non-empty" in resp.json()["message"]

        resp_invalid = self.client.post(
            "/api/check-urls/batch/", {"urls": "not-a-list"}, format="json"
        )
        assert resp_invalid.status_code == 400

    def test_batch_scan_max_limit_capped(self):
        urls = [f"https://domain-{i}.com/page" for i in range(70)]
        resp = self.client.post(
            "/api/check-urls/batch/",
            {"urls": urls},
            format="json",
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == 50  # Hard capped at 50

    def test_batch_scan_with_org_policy(self):
        OrgPolicy.objects.create(
            organization=self.org,
            custom_allowlist=["custom-safe-internal.corp"],
            custom_blocklist=["bad-actor.net"],
        )

        resp = self.client.post(
            "/api/check-urls/batch/",
            {
                "urls": [
                    "https://custom-safe-internal.corp/docs",
                    "https://bad-actor.net/malware",
                ]
            },
            format="json",
        )
        assert resp.status_code == 200
        results = resp.json()["results"]
        assert results[0]["verdict"] == "safe"
        assert results[0]["signals"]["org_policy_allowlist"] is True
        assert results[1]["verdict"] == "phishing"
        assert results[1]["signals"]["org_policy_blocklist"] is True
