import logging
from typing import Any

from accounts.models import AuditLog, Organization

logger = logging.getLogger(__name__)


def log_audit_event(
    organization: Organization,
    actor_user=None,
    action: str = "",
    target_type: str = "",
    target_id: str = "",
    ip_address: str | None = None,
    details: dict[str, Any] | None = None,
) -> AuditLog:
    """
    Creates an immutable audit log entry for enterprise governance and compliance.
    """
    try:
        entry = AuditLog.objects.create(
            organization=organization,
            actor_user=actor_user,
            action=action,
            target_type=target_type,
            target_id=str(target_id) if target_id else "",
            ip_address=ip_address,
            details=details or {},
        )
        return entry
    except Exception as exc:
        logger.error(f"Failed to record AuditLog entry: {exc}")
        raise
