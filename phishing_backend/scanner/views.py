import hashlib

from accounts.authentication import PhishGuardDualAuthentication
from accounts.models import UsageLog
from accounts.throttles import PlanBasedRateThrottle
from django.db import connection
from django.utils import timezone
from rest_framework import status
from rest_framework.decorators import (
    api_view,
    authentication_classes,
    permission_classes,
    throttle_classes,
)
from rest_framework.permissions import AllowAny
from rest_framework.response import Response

from .ml.predictor import ModelManager
from .models import URLScanResult


@api_view(["GET"])
@permission_classes([AllowAny])
def health_check_api(request):
    """
    Health check endpoint for container orchestrators and monitoring probes.
    Verifies DB connection and ML model readiness.
    """
    db_status = "connected"
    try:
        connection.ensure_connection()
    except Exception as exc:
        db_status = f"unhealthy: {exc}"

    model_manager = ModelManager.get_instance()
    model_loaded = model_manager.is_loaded

    is_healthy = db_status == "connected"
    status_code = status.HTTP_200_OK if is_healthy else status.HTTP_503_SERVICE_UNAVAILABLE

    return Response(
        {
            "status": "healthy" if is_healthy else "degraded",
            "database": db_status,
            "model_loaded": model_loaded,
            "version": "1.0.0",
            "timestamp": timezone.now().isoformat(),
        },
        status=status_code,
    )


def _resolve_org_and_user(request):
    """Helper to extract organization and user instance from request."""
    organization = getattr(request, "organization", None)
    user_instance = None
    if request.user and request.user.is_authenticated:
        from django.contrib.auth.models import User
        if isinstance(request.user, User):
            user_instance = request.user
            if not organization:
                membership = user_instance.memberships.first()
                if membership:
                    organization = membership.organization
        elif hasattr(request.user, "owner_user") and isinstance(request.user.owner_user, User):
            user_instance = request.user.owner_user
    return organization, user_instance


@api_view(["POST"])
@authentication_classes([PhishGuardDualAuthentication])
@permission_classes([AllowAny])
@throttle_classes([PlanBasedRateThrottle])
def check_url_api(request):
    url = str(request.data.get("url", "")).strip()

    if not url:
        return Response(
            {
                "success": False,
                "message": "URL is required.",
            },
            status=status.HTTP_400_BAD_REQUEST,
        )

    try:
        from .orchestrator import DetectionOrchestrator

        organization, user_instance = _resolve_org_and_user(request)
        result = DetectionOrchestrator.analyze(url, organization=organization)
        clean_url = result["clean_url"]
        domain = result["domain"]
        url_hash = hashlib.sha256(clean_url.encode("utf-8")).hexdigest()

        # 1. Privacy-compliant usage log (stores domain + SHA-256 hash)
        UsageLog.objects.create(
            organization=organization,
            user=user_instance,
            domain=domain,
            url_hash=url_hash,
            verdict=result["verdict"],
            risk_level=result["risk_level"],
            ip_address=request.META.get("REMOTE_ADDR"),
        )

        # 2. Legacy scan history model
        URLScanResult.objects.create(
            input_url=result["input_url"],
            clean_url=result["clean_url"],
            domain=domain,
            verdict=result["verdict"],
            risk_level=result["risk_level"],
            raw_phishing_probability=result["raw_phishing_probability"],
            phishing_probability=result["phishing_probability"],
            legitimate_probability=result["legitimate_probability"],
            reasons=result["reasons"],
            ip_address=request.META.get("REMOTE_ADDR"),
            user_agent=request.META.get("HTTP_USER_AGENT", ""),
        )

        return Response(
            {
                "success": True,
                "result": result,
            }
        )

    except Exception as e:
        return Response(
            {
                "success": False,
                "message": str(e),
            },
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@api_view(["POST"])
@authentication_classes([PhishGuardDualAuthentication])
@permission_classes([AllowAny])
@throttle_classes([PlanBasedRateThrottle])
def check_urls_batch_api(request):
    """
    Batch URL scanning endpoint for email clients (Gmail / Outlook Web) and security workflows.
    Accepts up to 50 URLs and optional sender_domain/sender_email for spoofing detection.
    """
    urls = request.data.get("urls", [])
    sender_domain = request.data.get("sender_domain") or request.data.get("sender_email")

    if not urls or not isinstance(urls, list):
        return Response(
            {
                "success": False,
                "message": "'urls' field must be a non-empty list of URLs.",
            },
            status=status.HTTP_400_BAD_REQUEST,
        )

    urls = [str(u).strip() for u in urls if str(u).strip()][:50]
    if not urls:
        return Response(
            {
                "success": False,
                "message": "No valid URLs provided in batch.",
            },
            status=status.HTTP_400_BAD_REQUEST,
        )

    try:
        from .orchestrator import DetectionOrchestrator

        organization, user_instance = _resolve_org_and_user(request)
        results = []
        usage_logs_to_create = []

        for url in urls:
            res = DetectionOrchestrator.analyze(
                url, organization=organization, sender_domain=sender_domain
            )
            clean_url = res["clean_url"]
            domain = res["domain"]
            url_hash = hashlib.sha256(clean_url.encode("utf-8")).hexdigest()

            usage_logs_to_create.append(
                UsageLog(
                    organization=organization,
                    user=user_instance,
                    domain=domain,
                    url_hash=url_hash,
                    verdict=res["verdict"],
                    risk_level=res["risk_level"],
                    ip_address=request.META.get("REMOTE_ADDR"),
                )
            )
            results.append(res)

        if usage_logs_to_create:
            UsageLog.objects.bulk_create(usage_logs_to_create)

        return Response(
            {
                "success": True,
                "count": len(results),
                "sender_domain": sender_domain,
                "results": results,
            }
        )

    except Exception as e:
        return Response(
            {
                "success": False,
                "message": str(e),
            },
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )

