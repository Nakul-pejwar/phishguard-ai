"""
Unit & integration tests for Phase 6 Team Dashboard, Tenant Isolation, Policy, and Incident Triage.
"""

import pytest
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient

from accounts.dashboard.alerts import send_threat_alert
from accounts.models import (
    Membership,
    Organization,
    OrgPolicy,
    Plan,
    UsageLog,
)
from scanner.orchestrator import DetectionOrchestrator

User = get_user_model()


@pytest.fixture
def org_a_setup():
    user_a = User.objects.create_user(username="admin_a", email="admin_a@orga.com", password="Password123!")
    org_a = Organization.objects.create(name="Organization Alpha", slug="org-alpha")
    Membership.objects.create(user=user_a, organization=org_a, role=Membership.ROLE_ADMIN)

    team_plan, _ = Plan.objects.get_or_create(
        slug="team",
        defaults={
            "name": "Team",
            "daily_scan_limit": 2500,
            "price_inr": 1999.00,
            "features": {"api_access": True, "team_seats": 5, "team_reporting": True},
        },
    )
    from accounts.models import Subscription
    Subscription.objects.create(organization=org_a, plan=team_plan, status=Subscription.STATUS_ACTIVE)

    # Seed logs for Org A
    UsageLog.objects.create(
        organization=org_a,
        user=user_a,
        domain="malicious-threat-a.xyz",
        url_hash="hash_a1",
        verdict="phishing",
        risk_level="Critical",
    )
    UsageLog.objects.create(
        organization=org_a,
        user=user_a,
        domain="safe-bank-a.com",
        url_hash="hash_a2",
        verdict="safe",
        risk_level="Safe",
    )
    return {"user": user_a, "org": org_a}


@pytest.fixture
def org_b_setup():
    user_b = User.objects.create_user(username="admin_b", email="admin_b@orgb.com", password="Password123!")
    org_b = Organization.objects.create(name="Organization Beta", slug="org-beta")
    Membership.objects.create(user=user_b, organization=org_b, role=Membership.ROLE_ADMIN)

    # Seed logs for Org B
    UsageLog.objects.create(
        organization=org_b,
        user=user_b,
        domain="exclusive-threat-b.top",
        url_hash="hash_b1",
        verdict="phishing",
        risk_level="High",
    )
    return {"user": user_b, "org": org_b}


@pytest.mark.django_db
def test_dashboard_strict_tenant_isolation(org_a_setup, org_b_setup):
    client = APIClient()
    client.force_authenticate(user=org_a_setup["user"])

    # 1. Overview KPIs for Org A
    resp_kpi = client.get("/api/dashboard/overview/")
    assert resp_kpi.status_code == 200
    assert resp_kpi.data["total_scans_30d"] == 2
    assert resp_kpi.data["blocked_threats_30d"] == 1

    # 2. Top Threats for Org A must NOT show Org B's threats
    resp_top = client.get("/api/dashboard/top-threats/")
    assert resp_top.status_code == 200
    top_domains = [d["domain"] for d in resp_top.data["top_domains"]]
    assert "malicious-threat-a.xyz" in top_domains
    assert "exclusive-threat-b.top" not in top_domains

    # 3. CSV Export must only contain Org A's records
    resp_csv = client.get("/api/dashboard/export/csv/")
    assert resp_csv.status_code == 200
    csv_content = resp_csv.content.decode("utf-8")
    assert "malicious-threat-a.xyz" in csv_content
    assert "exclusive-threat-b.top" not in csv_content


@pytest.mark.django_db
def test_org_policy_allowlist_and_blocklist_enforcement(org_a_setup):
    org = org_a_setup["org"]
    policy, _ = OrgPolicy.objects.get_or_create(organization=org)
    policy.custom_allowlist = ["internal-tools.corp.local"]
    policy.custom_blocklist = ["prohibited-social.com"]
    policy.save()

    # Allowlist test
    res_allow = DetectionOrchestrator.analyze("http://internal-tools.corp.local/login", organization=org)
    assert res_allow["verdict"] == "safe"
    assert "allowlisted" in res_allow["reasons"][0].lower()

    # Blocklist test
    res_block = DetectionOrchestrator.analyze("http://prohibited-social.com/feed", organization=org)
    assert res_block["verdict"] == "phishing"
    assert "blocked" in res_block["reasons"][0].lower()


@pytest.mark.django_db
def test_team_member_invitation_lifecycle(org_a_setup):
    client = APIClient()
    client.force_authenticate(user=org_a_setup["user"])

    # 1. Invite a new member
    invite_resp = client.post(
        "/api/dashboard/members/invite/",
        {"email": "new_security_analyst@orga.com", "role": "member"},
    )
    assert invite_resp.status_code == 201
    token = invite_resp.data["token"]
    assert token is not None

    # 2. New user signs up and accepts the invite
    invited_user = User.objects.create_user(
        username="new_analyst",
        email="new_security_analyst@orga.com",
        password="AnalystPassword123!",
    )
    client.force_authenticate(user=invited_user)

    accept_resp = client.post("/api/dashboard/members/accept-invite/", {"token": token})
    assert accept_resp.status_code == 200
    assert "Successfully joined" in accept_resp.data["message"]

    # Verify membership created
    membership = Membership.objects.filter(user=invited_user, organization=org_a_setup["org"]).first()
    assert membership is not None
    assert membership.role == "member"


@pytest.mark.django_db
def test_incident_reporting_and_resolution_queue(org_a_setup):
    admin_user = org_a_setup["user"]
    org = org_a_setup["org"]

    client = APIClient()
    client.force_authenticate(user=admin_user)

    # 1. Submit incident report
    create_resp = client.post(
        "/api/dashboard/reports/",
        {
            "url": "http://misidentified-partner.com/login",
            "report_type": "false_positive",
            "notes": "Legitimate vendor partner portal misidentified as phishing.",
        },
    )
    assert create_resp.status_code == 201
    report_id = create_resp.data["id"]

    # 2. List reports
    list_resp = client.get("/api/dashboard/reports/")
    assert list_resp.status_code == 200
    assert len(list_resp.data["reports"]) == 1

    # 3. Resolve report as False Positive with auto-allowlist
    resolve_resp = client.patch(
        f"/api/dashboard/reports/{report_id}/resolve/",
        {"status": "false_positive", "add_to_allowlist": True},
    )
    assert resolve_resp.status_code == 200
    assert resolve_resp.data["status"] == "false_positive"

    # Verify domain added to OrgPolicy custom_allowlist
    policy = OrgPolicy.objects.get(organization=org)
    assert "misidentified-partner.com" in policy.custom_allowlist


@pytest.mark.django_db
def test_threat_alert_dispatcher(org_a_setup):
    org = org_a_setup["org"]
    policy, _ = OrgPolicy.objects.get_or_create(organization=org)
    policy.alert_webhook_url = "https://hooks.slack.com/services/T00/B00/mock123"
    policy.save()

    # Trigger alert dispatcher (gracefully handles network mock failure)
    result = send_threat_alert(
        organization=org,
        domain="urgent-sbi-kyc-scam.xyz",
        verdict="phishing",
        risk_level="Critical",
        reported_by_email="analyst@orga.com",
    )
    # Since mock url is unreachable in test environment, returns False without raising exception
    assert result is False
