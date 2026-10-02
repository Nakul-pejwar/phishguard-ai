import csv

from django.http import HttpResponse
from django.utils.dateparse import parse_datetime
from rest_framework import status
from rest_framework.decorators import (
    api_view,
    authentication_classes,
    permission_classes,
)
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from accounts.authentication import PhishGuardDualAuthentication
from accounts.models import AuditLog
from accounts.permissions import IsOrgAdmin


def _filter_audit_logs(logs, request):
    """Filters audit logs by action, actor, and date ranges."""
    action_filter = request.GET.get("action")
    if action_filter:
        logs = logs.filter(action=action_filter)

    actor_filter = request.GET.get("actor")
    if actor_filter:
        logs = logs.filter(actor_user__email__icontains=actor_filter)

    start_date = request.GET.get("start_date")
    if start_date:
        parsed_start = parse_datetime(start_date)
        if parsed_start:
            logs = logs.filter(created_at__gte=parsed_start)

    end_date = request.GET.get("end_date")
    if end_date:
        parsed_end = parse_datetime(end_date)
        if parsed_end:
            logs = logs.filter(created_at__lte=parsed_end)

    return logs


def _export_audit_logs_csv(logs, org_slug):
    """Renders audit logs as downloadable CSV."""
    response = HttpResponse(content_type="text/csv")
    response["Content-Disposition"] = f'attachment; filename="phishguard_audit_log_{org_slug}.csv"'

    writer = csv.writer(response)
    writer.writerow(["Timestamp (UTC)", "Actor", "Action", "Target Type", "Target ID", "IP Address", "Details"])

    for item in logs[:5000]:
        actor = item.actor_user.email if item.actor_user else "System"
        writer.writerow([
            item.created_at.isoformat(),
            actor,
            item.action,
            item.target_type,
            item.target_id,
            item.ip_address or "N/A",
            str(item.details),
        ])
    return response


@api_view(["GET"])
@authentication_classes([PhishGuardDualAuthentication])
@permission_classes([IsAuthenticated, IsOrgAdmin])
def audit_logs_api(request):
    """
    Returns filterable, paginated audit logs or a CSV audit export.
    """
    membership = request.user.memberships.first()
    if not membership:
        return Response({"error": "No organization found."}, status=status.HTTP_404_NOT_FOUND)

    org = membership.organization
    logs = AuditLog.objects.filter(organization=org).select_related("actor_user")
    logs = _filter_audit_logs(logs, request)

    if request.GET.get("export") == "csv":
        return _export_audit_logs_csv(logs, org.slug)

    limit = min(int(request.GET.get("limit", 50)), 100)
    offset = int(request.GET.get("offset", 0))
    total_count = logs.count()
    page_items = logs[offset: offset + limit]

    results = []
    for item in page_items:
        actor = item.actor_user.email if item.actor_user else "System"
        results.append({
            "id": item.id,
            "created_at": item.created_at.isoformat(),
            "actor": actor,
            "action": item.action,
            "target_type": item.target_type,
            "target_id": item.target_id,
            "ip_address": item.ip_address,
            "details": item.details,
        })

    return Response({
        "success": True,
        "total": total_count,
        "offset": offset,
        "limit": limit,
        "results": results,
    })

