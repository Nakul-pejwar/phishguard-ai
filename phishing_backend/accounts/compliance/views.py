from django.contrib.auth.models import User
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
from accounts.models import DataRetentionPolicy, Membership, UsageLog
from accounts.permissions import IsOrgAdmin

from .tasks import purge_expired_privacy_logs


@api_view(["GET", "PUT"])
@authentication_classes([PhishGuardDualAuthentication])
@permission_classes([IsAuthenticated, IsOrgAdmin])
def retention_policy_api(request):
    """
    Views or updates the organization's DPDP Data Retention Policy.
    """
    membership = request.user.memberships.first()
    if not membership:
        return Response({"error": "No organization found."}, status=status.HTTP_404_NOT_FOUND)

    org = membership.organization
    policy, _ = DataRetentionPolicy.objects.get_or_create(
        organization=org,
        defaults={"retention_days": 90, "auto_purge_enabled": True},
    )

    if request.method == "GET":
        return Response({
            "retention_days": policy.retention_days,
            "auto_purge_enabled": policy.auto_purge_enabled,
            "anonymize_on_purge": policy.anonymize_on_purge,
            "updated_at": policy.updated_at.isoformat() if policy.updated_at else None,
        })

    days = int(request.data.get("retention_days", policy.retention_days))
    if days < 7 or days > 730:
        return Response(
            {"error": "Retention days must be between 7 days and 730 days (2 years)."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    policy.retention_days = days
    if "auto_purge_enabled" in request.data:
        policy.auto_purge_enabled = bool(request.data["auto_purge_enabled"])
    policy.save()

    log_audit_event(
        organization=org,
        actor_user=request.user,
        action="compliance.retention.update",
        target_type="DataRetentionPolicy",
        target_id=str(policy.id),
        ip_address=request.META.get("REMOTE_ADDR"),
        details={"retention_days": policy.retention_days, "auto_purge": policy.auto_purge_enabled},
    )

    return Response({"success": True, "message": "Retention policy updated successfully."})


@api_view(["POST"])
@authentication_classes([PhishGuardDualAuthentication])
@permission_classes([IsAuthenticated, IsOrgAdmin])
def erasure_request_api(request):
    """
    Executes a Right to Erasure / Data Deletion request under Indian DPDP Act & GDPR.
    Anonymizes all scan usage records and removes employee membership from the organization.
    Input: {"email": "user@bankcorp.in"}
    """
    membership = request.user.memberships.first()
    if not membership:
        return Response({"error": "No organization found."}, status=status.HTTP_404_NOT_FOUND)

    org = membership.organization
    target_email = request.data.get("email", "").strip().lower()

    if not target_email:
        return Response({"error": "Target user email is required."}, status=status.HTTP_400_BAD_REQUEST)

    try:
        target_user = User.objects.get(email=target_email)
    except User.DoesNotExist:
        return Response({"error": "User with this email not found."}, status=status.HTTP_404_NOT_FOUND)

    # 1. Anonymize user FK on all telemetry logs for this organization
    anonymized_count = UsageLog.objects.filter(organization=org, user=target_user).update(
        user=None, ip_address="0.0.0.0"
    )

    # 2. Remove user membership in this organization
    Membership.objects.filter(organization=org, user=target_user).delete()

    # 3. Log immutable audit entry
    log_audit_event(
        organization=org,
        actor_user=request.user,
        action="compliance.erasure.processed",
        target_type="User",
        target_id=str(target_user.id),
        ip_address=request.META.get("REMOTE_ADDR"),
        details={"target_email": target_email, "anonymized_logs": anonymized_count},
    )

    return Response({
        "success": True,
        "message": f"Right to Erasure processed successfully for {target_email}.",
        "anonymized_logs": anonymized_count,
    })


@api_view(["POST"])
@authentication_classes([PhishGuardDualAuthentication])
@permission_classes([IsAuthenticated, IsOrgAdmin])
def trigger_purge_api(request):
    """
    On-demand data retention purge trigger for administrators.
    """
    membership = request.user.memberships.first()
    if not membership:
        return Response({"error": "No organization found."}, status=status.HTTP_404_NOT_FOUND)

    org = membership.organization
    purged_count = purge_expired_privacy_logs(organization_id=org.id)

    log_audit_event(
        organization=org,
        actor_user=request.user,
        action="compliance.purge.manual",
        target_type="UsageLog",
        target_id=str(org.id),
        ip_address=request.META.get("REMOTE_ADDR"),
        details={"purged_count": purged_count},
    )

    return Response({
        "success": True,
        "purged_records": purged_count,
        "message": f"Retention purge complete. {purged_count} expired records removed.",
    })
