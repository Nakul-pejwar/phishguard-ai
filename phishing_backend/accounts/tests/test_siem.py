from unittest.mock import MagicMock, patch

import pytest
from django.contrib.auth.models import User
from rest_framework.test import APIClient

from accounts.models import Membership, Organization, SIEMConfiguration
from accounts.siem.tasks import build_siem_payload, forward_threat_to_siem


@pytest.mark.django_db
class TestSIEMIntegration:
    def setup_method(self):
        self.client = APIClient()
        self.user = User.objects.create_user(
            username="siemadmin",
            email="siemadmin@bankcorp.in",
            password="adminpassword123",
        )
        self.org = Organization.objects.create(name="Bank Corp India", slug="bankcorp")
        Membership.objects.create(
            organization=self.org,
            user=self.user,
            role=Membership.ROLE_ADMIN,
        )
        self.client.force_authenticate(user=self.user)

    def test_build_siem_payload_formats(self):
        incident = {
            "domain": "hdfc-kyc-verify.xyz",
            "risk_level": "Critical Risk",
            "verdict": "phishing",
        }

        # Splunk HEC
        splunk_p, _ = build_siem_payload(SIEMConfiguration.TYPE_SPLUNK, incident, "Bank Corp")
        assert splunk_p["sourcetype"] == "phishguard:security:incident"
        assert splunk_p["event"]["domain"] == "hdfc-kyc-verify.xyz"

        # Datadog
        dd_p, _ = build_siem_payload(SIEMConfiguration.TYPE_DATADOG, incident, "Bank Corp")
        assert dd_p["ddsource"] == "phishguard"
        assert "Bank Corp" in dd_p["ddtags"]

        # Sentinel / Webhook
        sentinel_p, _ = build_siem_payload(SIEMConfiguration.TYPE_SENTINEL, incident, "Bank Corp")
        assert sentinel_p["event_type"] == "phishguard.security.threat"

    def test_siem_config_api(self):
        # GET (initial create)
        resp = self.client.get("/api/siem/config/")
        assert resp.status_code == 200
        assert resp.json()["siem_type"] == "generic_webhook"

        # PUT update
        update_resp = self.client.put(
            "/api/siem/config/",
            {
                "siem_type": "splunk_hec",
                "endpoint_url": "https://splunk.bankcorp.in:8088/services/collector",
                "auth_token": "SPLUNK-HEC-TOKEN-12345",
                "is_active": True,
            },
            format="json",
        )
        assert update_resp.status_code == 200
        config = self.org.siem_config
        assert config.siem_type == "splunk_hec"
        assert config.auth_token == "SPLUNK-HEC-TOKEN-12345"
        assert config.is_active is True

    @patch("accounts.siem.tasks.urlopen")
    def test_forward_threat_to_siem_task(self, mock_urlopen):
        mock_response = MagicMock()
        mock_response.getcode.return_value = 200
        mock_response.__enter__.return_value = mock_response
        mock_urlopen.return_value = mock_response

        SIEMConfiguration.objects.create(
            organization=self.org,
            siem_type=SIEMConfiguration.TYPE_SPLUNK,
            endpoint_url="https://splunk.bankcorp.in:8088/services/collector",
            auth_token="TEST-TOKEN",
            is_active=True,
            min_severity="high",
        )

        incident_data = {
            "domain": "fake-axis-login.xyz",
            "risk_level": "high",
            "verdict": "phishing",
        }

        res = forward_threat_to_siem(incident_data, self.org.id)
        assert "Successfully delivered" in res
        assert mock_urlopen.called

        # Test minimum severity filtering (skip low severity)
        low_sev_incident = {
            "domain": "safe-site.com",
            "risk_level": "low",
            "verdict": "safe",
        }
        res_skipped = forward_threat_to_siem(low_sev_incident, self.org.id)
        assert "skipped" in res_skipped

    @patch("accounts.siem.views.forward_threat_to_siem.delay")
    def test_siem_test_api(self, mock_delay):
        resp = self.client.post("/api/siem/test/")
        assert resp.status_code == 200
        assert resp.json()["success"] is True
        assert mock_delay.called

