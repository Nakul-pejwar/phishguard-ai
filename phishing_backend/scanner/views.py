import hashlib

from accounts.authentication import PhishGuardDualAuthentication
from accounts.models import UsageLog
from accounts.throttles import PlanBasedRateThrottle
from rest_framework import status
from rest_framework.decorators import (
    api_view,
    authentication_classes,
    permission_classes,
    throttle_classes,
)
from rest_framework.permissions import AllowAny
from rest_framework.response import Response

from .ml.predictor import predict_phishing_url
from .models import URLScanResult


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
        result = predict_phishing_url(url)
        clean_url = result["clean_url"]
        domain = result["domain"]
        url_hash = hashlib.sha256(clean_url.encode("utf-8")).hexdigest()

        # Resolve organization & user
        organization = getattr(request, "organization", None)
        user = request.user if request.user and request.user.is_authenticated else None
        user_instance = user if (user and hasattr(user, "id") and user.id) else None

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
