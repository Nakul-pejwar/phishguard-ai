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

        result = DetectionOrchestrator.analyze(url)
        clean_url = result["clean_url"]
        domain = result["domain"]
        url_hash = hashlib.sha256(clean_url.encode("utf-8")).hexdigest()

        # Resolve organization & real User instance for ForeignKey
        organization = getattr(request, "organization", None)
        user_instance = None
        if request.user and request.user.is_authenticated:
            from django.contrib.auth.models import User
            if isinstance(request.user, User):
                user_instance = request.user
            elif hasattr(request.user, "owner_user") and isinstance(request.user.owner_user, User):
                user_instance = request.user.owner_user

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
