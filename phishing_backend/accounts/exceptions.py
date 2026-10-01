from rest_framework import exceptions
from rest_framework.response import Response
from rest_framework.views import exception_handler


def custom_exception_handler(exc, context):
    # Handle Throttled exceptions with custom structured dictionary
    if isinstance(exc, exceptions.Throttled) and isinstance(exc.detail, dict):
        clean_data = {
            "success": False,
            "error": str(exc.detail.get("error", "rate_limit_exceeded")),
            "message": str(exc.detail.get("message", "Rate limit exceeded.")),
            "limit": int(exc.detail.get("limit", 0)),
            "used": int(exc.detail.get("used", 0)),
            "plan": str(exc.detail.get("plan", "")),
        }
        return Response(clean_data, status=429)

    response = exception_handler(exc, context)

    if response is not None:
        if isinstance(response.data, dict) and "detail" in response.data:
            detail = response.data["detail"]
            if isinstance(detail, dict):
                response.data = {
                    k: False if str(v) == "False" else (True if str(v) == "True" else (int(str(v)) if str(v).isdigit() else str(v)))
                    for k, v in detail.items()
                }
            else:
                response.data = {
                    "success": False,
                    "message": str(detail),
                }
        elif isinstance(response.data, list):
            response.data = {
                "success": False,
                "errors": response.data,
            }

    return response
