from rest_framework import status
from rest_framework.decorators import (
    api_view,
    authentication_classes,
    permission_classes,
)
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from accounts.audit.services import log_audit_event
from accounts.authentication import PhishGuardDualAuthentication
from accounts.models import SIEMConfiguration
from accounts.permissions import IsOrgAdmin

from .tasks import forward_threat_to_siem


@api_view(["GET", "PUT", "POST"])
@authentication_classes([PhishGuardDualAuthentication])
@permission_classes([IsAuthenticated, IsOrgAdmin])
def siem_config_api(request):
    """
    Manages enterprise SIEM forwarder settings (Splunk, Microsoft Sentinel, Datadog, Webhook).
    """
    membership = request.user.memberships.first()
    if not membership:
        return Response({"error": "No organization found."}, status=status.HTTP_404_NOT_FOUND)

    org = membership.organization
    config, created = SIEMConfiguration.objects.get_or_create(
        organization=org,
        defaults={"endpoint_url": "https://example.com/webhook", "is_active": False},
    )

    if request.method == "GET":
        # Mask auth token for security
        masked_token = (config.auth_token[:4] + "********") if len(config.auth_token) > 4 else "********" if config.auth_token else ""
        return Response({
            "siem_type": config.siem_type,
            "endpoint_url": config.endpoint_url,
            "auth_header_name": config.auth_header_name,
            "auth_token_masked": masked_token,
            "min_severity": config.min_severity,
            "is_active": config.is_active,
            "last_event_sent_at": config.last_event_sent_at.isoformat() if config.last_event_sent_at else None,
        })

    # PUT / POST update
    data = request.data
    config.siem_type = data.get("siem_type", config.siem_type)
    config.endpoint_url = data.get("endpoint_url", config.endpoint_url)
    config.auth_header_name = data.get("auth_header_name", config.auth_header_name)
    if "auth_token" in data and data["auth_token"]:
        config.auth_token = data["auth_token"]
    config.min_severity = data.get("min_severity", config.min_severity)
    config.is_active = data.get("is_active", config.is_active)
    config.save()

    log_audit_event(
        organization=org,
        actor_user=request.user,
        action="siem.config.update",
        target_type="SIEMConfiguration",
        target_id=str(config.id),
        ip_address=request.META.get("REMOTE_ADDR"),
        details={"siem_type": config.siem_type, "is_active": config.is_active},
    )

    return Response({"success": True, "message": "SIEM configuration updated successfully."})


@api_view(["POST"])
@authentication_classes([PhishGuardDualAuthentication])
@permission_classes([IsAuthenticated, IsOrgAdmin])
def siem_test_api(request):
    """
    Triggers a synthetic test security event to verify SIEM connectivity.
    """
    membership = request.user.memberships.first()
    if not membership:
        return Response({"error": "No organization found."}, status=status.HTTP_404_NOT_FOUND)

    org = membership.organization
    test_incident = {
        "event_id": "test-sec-probe-001",
        "domain": "phish-test-lookalike.xyz",
        "risk_level": "Critical Risk",
        "verdict": "phishing",
        "reasons": ["Synthetic validation probe for enterprise SIEM integration."],
        "test_event": True,
    }

    forward_threat_to_siem.delay(test_incident, org.id)

    return Response({
        "success": True,
        "message": "Synthetic SIEM security event dispatched.",
    })
