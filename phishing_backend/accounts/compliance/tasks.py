import logging
from datetime import timedelta

from celery import shared_task
from django.utils import timezone

from accounts.models import Organization, UsageLog

logger = logging.getLogger(__name__)


@shared_task
def purge_expired_privacy_logs(organization_id: int | None = None) -> int:
    """
    Automated data retention purge task aligned with India's DPDP Act and GDPR.
    Purges scan telemetry older than the organization's retention limit (default 90 days).
    """
    total_purged = 0
    now = timezone.now()

    if organization_id:
        orgs = Organization.objects.filter(id=organization_id)
    else:
        orgs = Organization.objects.all()

    for org in orgs:
        policy = getattr(org, "retention_policy", None)
        retention_days = policy.retention_days if policy else 90
        auto_purge = policy.auto_purge_enabled if policy else True

        if not auto_purge:
            continue

        cutoff_date = now - timedelta(days=retention_days)
        deleted_count, _ = UsageLog.objects.filter(
            organization=org,
            created_at__lt=cutoff_date,
        ).delete()

        total_purged += deleted_count
        if deleted_count > 0:
            logger.info(f"DPDP Auto-Purge: Deleted {deleted_count} expired logs for Org '{org.name}' older than {retention_days} days.")

    return total_purged
