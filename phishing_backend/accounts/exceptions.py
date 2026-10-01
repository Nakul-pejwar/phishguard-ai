from rest_framework.views import exception_handler


def custom_exception_handler(exc, context):
    response = exception_handler(exc, context)

    if response is not None:
        if isinstance(response.data, dict) and "detail" in response.data:
            detail = response.data["detail"]
            if isinstance(detail, dict):
                # Flatten structured details (like throttled payload)
                response.data = detail
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
