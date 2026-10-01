from rest_framework.views import exception_handler


def _clean_value(val):
    if isinstance(val, dict):
        return {k: _clean_value(v) for k, v in val.items()}
    if isinstance(val, list):
        return [_clean_value(i) for i in val]
    val_str = str(val).strip()
    if val_str == "False":
        return False
    if val_str == "True":
        return True
    if val_str.isdigit():
        return int(val_str)
    return str(val)


def custom_exception_handler(exc, context):
    response = exception_handler(exc, context)

    if response is not None:
        if isinstance(response.data, dict) and "detail" in response.data:
            detail = response.data["detail"]
            if isinstance(detail, dict):
                response.data = _clean_value(detail)
            else:
                response.data = {
                    "success": False,
                    "message": str(detail),
                }
        elif isinstance(response.data, list):
            response.data = {
                "success": False,
                "errors": _clean_value(response.data),
            }

    return response
