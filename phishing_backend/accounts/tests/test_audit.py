import pytest
from django.contrib.auth.models import User
from rest_framework.test import APIClient

from accounts.audit.services import log_audit_event
from accounts.models import Membership, Organization


@pytest.mark.django_db
class TestEnterpriseAuditLog:
    def setup_method(self):
        self.client = APIClient()
        self.user = User.objects.create_user(
            username="secadmin",
            email="secadmin@bankcorp.in",
            password="adminpassword123",
        )
        self.org = Organization.objects.create(name="Bank Corp India", slug="bankcorp")
        self.other_org = Organization.objects.create(name="Other Corp", slug="othercorp")

        Membership.objects.create(
            organization=self.org,
            user=self.user,
            role=Membership.ROLE_ADMIN,
        )
        self.client.force_authenticate(user=self.user)

    def test_log_audit_event_and_immutability(self):
        entry = log_audit_event(
            organization=self.org,
            actor_user=self.user,
            action="policy.blocklist.add",
            target_type="Domain",
            target_id="evil-phish.xyz",
            ip_address="192.168.1.100",
            details={"reason": "Manual SOC block"},
        )
        assert entry.id is not None
        assert entry.action == "policy.blocklist.add"
        assert entry.details["reason"] == "Manual SOC block"

        # Verify Immutable Constraints
        with pytest.raises(PermissionError):
            entry.action = "tampered.action"
            entry.save()

        with pytest.raises(PermissionError):
            entry.delete()

    def test_audit_logs_api_and_isolation(self):
        # Create events for this org
        log_audit_event(self.org, self.user, "user.invite", "User", "user1@bankcorp.in")
        log_audit_event(self.org, self.user, "policy.update", "OrgPolicy", "1")

        # Create event for another org
        log_audit_event(self.other_org, None, "system.event", "System", "0")

        resp = self.client.get("/api/audit/logs/")
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        assert data["total"] == 2
        assert len(data["results"]) == 2

        # Verify filter by action
        resp_filtered = self.client.get("/api/audit/logs/?action=policy.update")
        assert resp_filtered.status_code == 200
        assert resp_filtered.json()["total"] == 1

        # Verify CSV export
        resp_csv = self.client.get("/api/audit/logs/?export=csv")
        assert resp_csv.status_code == 200
        assert resp_csv["Content-Type"] == "text/csv"
        csv_content = resp_csv.content.decode("utf-8")
        assert "Timestamp (UTC),Actor,Action" in csv_content
        assert "policy.update" in csv_content
