from datetime import timedelta

import pytest
from django.contrib.auth.models import User
from django.utils import timezone
from rest_framework.test import APIClient

from accounts.compliance.tasks import purge_expired_privacy_logs
from accounts.models import DataRetentionPolicy, Membership, Organization, UsageLog


@pytest.mark.django_db
class TestDPDPComplianceAndRetention:
    def setup_method(self):
        self.client = APIClient()
        self.user = User.objects.create_user(
            username="dpo@bankcorp.in",
            email="dpo@bankcorp.in",
            password="adminpassword123",
        )
        self.employee = User.objects.create_user(
            username="employee@bankcorp.in",
            email="employee@bankcorp.in",
            password="password123",
        )
        self.org = Organization.objects.create(name="Bank Corp India", slug="bankcorp")
        Membership.objects.create(
            organization=self.org,
            user=self.user,
            role=Membership.ROLE_ADMIN,
        )
        Membership.objects.create(
            organization=self.org,
            user=self.employee,
            role=Membership.ROLE_MEMBER,
        )
        self.client.force_authenticate(user=self.user)

    def test_retention_policy_api(self):
        # GET
        resp = self.client.get("/api/compliance/retention/")
        assert resp.status_code == 200
        assert resp.json()["retention_days"] == 90

        # PUT update
        update_resp = self.client.put(
            "/api/compliance/retention/",
            {"retention_days": 180, "auto_purge_enabled": True},
            format="json",
        )
        assert update_resp.status_code == 200
        assert self.org.retention_policy.retention_days == 180

    def test_data_retention_auto_purge_task(self):
        DataRetentionPolicy.objects.create(
            organization=self.org,
            retention_days=30,
            auto_purge_enabled=True,
        )

        now = timezone.now()
        # Old log (45 days old)
        old_log = UsageLog.objects.create(
            organization=self.org,
            user=self.employee,
            domain="old-phish.xyz",
            url_hash="hash1",
            verdict="phishing",
            risk_level="high",
        )
        # Manually backdate created_at
        UsageLog.objects.filter(id=old_log.id).update(created_at=now - timedelta(days=45))

        # Recent log (5 days old)
        recent_log = UsageLog.objects.create(
            organization=self.org,
            user=self.employee,
            domain="recent-safe.com",
            url_hash="hash2",
            verdict="safe",
            risk_level="Safe",
        )
        UsageLog.objects.filter(id=recent_log.id).update(created_at=now - timedelta(days=5))

        purged = purge_expired_privacy_logs(organization_id=self.org.id)
        assert purged == 1
        assert not UsageLog.objects.filter(id=old_log.id).exists()
        assert UsageLog.objects.filter(id=recent_log.id).exists()

    def test_right_to_erasure_api(self):
        # Create user logs
        UsageLog.objects.create(
            organization=self.org,
            user=self.employee,
            domain="sample.com",
            url_hash="hash-user",
            verdict="safe",
            risk_level="Safe",
            ip_address="10.0.0.5",
        )

        resp = self.client.post(
            "/api/compliance/erasure-request/",
            {"email": "employee@bankcorp.in"},
            format="json",
        )
        assert resp.status_code == 200
        assert resp.json()["success"] is True

        # Verify employee logs anonymized
        user_logs = UsageLog.objects.filter(organization=self.org, user=self.employee)
        assert user_logs.count() == 0

        anonymized_logs = UsageLog.objects.filter(organization=self.org, url_hash="hash-user")
        assert anonymized_logs.first().user is None
        assert anonymized_logs.first().ip_address == "0.0.0.0"

        # Verify membership removed
        assert not Membership.objects.filter(organization=self.org, user=self.employee).exists()

    def test_trigger_manual_purge_api(self):
        resp = self.client.post("/api/compliance/purge/")
        assert resp.status_code == 200
        assert "purged_records" in resp.json()
