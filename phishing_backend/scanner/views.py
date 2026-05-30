from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status

from .ml.predictor import predict_phishing_url
from .models import URLScanResult


@api_view(["POST"])
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

        URLScanResult.objects.create(
            input_url=result["input_url"],
            clean_url=result["clean_url"],
            domain=result["domain"],
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