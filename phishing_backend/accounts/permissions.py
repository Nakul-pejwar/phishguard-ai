"""
PhishGuard AI — Core Permissions
"""

from rest_framework.permissions import BasePermission

from accounts.billing.permissions import HasFeaturePermission, IsOrgAdminOrOwner
from accounts.models import Membership


class IsOrgAdmin(BasePermission):
    """Allows access only to organization admins or owners."""

    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False
        membership = Membership.objects.filter(
            user=request.user,
            role__in=[Membership.ROLE_ADMIN, Membership.ROLE_OWNER],
        ).first()
        return membership is not None


__all__ = ["IsOrgAdmin", "IsOrgAdminOrOwner", "HasFeaturePermission"]
