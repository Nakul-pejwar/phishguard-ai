"""
PhishGuard AI — Plan Feature & Role Permissions
"""

from rest_framework.permissions import BasePermission

from accounts.models import Membership


class IsOrgAdminOrOwner(BasePermission):
    """Allows access only to organization admins or owners."""

    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False
        membership = Membership.objects.filter(
            user=request.user,
            role__in=[Membership.ROLE_ADMIN, Membership.ROLE_OWNER],
        ).first()
        return membership is not None


class HasFeaturePermission:
    """Factory creating a DRF Permission checking if the user's org plan has a specific feature enabled."""

    def __init__(self, feature_name: str):
        self.feature_name = feature_name

    def __call__(self):
        feature_name = self.feature_name

        class _FeaturePermission(BasePermission):
            message = f"Feature '{feature_name}' is not enabled on your current subscription plan. Please upgrade."

            def has_permission(self, request, view):
                if not request.user or not request.user.is_authenticated:
                    return False
                membership = Membership.objects.filter(user=request.user).select_related("organization").first()
                if not membership:
                    return False
                active_plan = membership.organization.get_active_plan()
                return bool(active_plan.features.get(feature_name, False))

        return _FeaturePermission()
