from django.utils import timezone
from rest_framework import exceptions, throttling

from .models import UsageLog


class PlanBasedRateThrottle(throttling.BaseThrottle):
    """
    Plan-aware DRF Throttle:
    - Free Plan: 20 scans per day
    - Pro Plan: 1,000 scans per day (or unlimited if configured)
    - Team Plan: 10,000 scans per day
    - Anonymous (no auth): 5 trial scans per day per IP
    """

    ANONYMOUS_DAILY_LIMIT = 5

    def allow_request(self, request, view):
        today_start = timezone.now().replace(hour=0, minute=0, second=0, microsecond=0)

        # 1. Authenticated User / API Key
        organization = getattr(request, "organization", None)
        user = getattr(request, "user", None)

        if user and user.is_authenticated and organization:
            plan = organization.get_active_plan()
            daily_limit = plan.daily_scan_limit

            # -1 represents unlimited
            if daily_limit == -1:
                return True

            used_count = UsageLog.objects.filter(
                organization=organization,
                created_at__gte=today_start,
            ).count()

            if used_count >= daily_limit:
                raise exceptions.Throttled(
                    detail={
                        "success": False,
                        "error": "rate_limit_exceeded",
                        "message": f"Daily scan quota reached for {plan.name} plan ({daily_limit} scans/day). Please upgrade for higher limits.",
                        "limit": daily_limit,
                        "used": used_count,
                        "plan": plan.slug,
                    }
                )
            return True

        # 2. Anonymous Request (IP-based trial quota)
        client_ip = self.get_client_ip(request)
        used_count = UsageLog.objects.filter(
            ip_address=client_ip,
            organization__isnull=True,
            created_at__gte=today_start,
        ).count()

        if used_count >= self.ANONYMOUS_DAILY_LIMIT:
            raise exceptions.Throttled(
                detail={
                    "success": False,
                    "error": "trial_quota_exceeded",
                    "message": f"Anonymous trial quota of {self.ANONYMOUS_DAILY_LIMIT} scans/day exceeded. Please sign up or log in to continue.",
                    "limit": self.ANONYMOUS_DAILY_LIMIT,
                    "used": used_count,
                    "plan": "anonymous_trial",
                }
            )

        return True

    def get_client_ip(self, request) -> str:
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
        if x_forwarded_for:
            return x_forwarded_for.split(",")[0].strip()
        return request.META.get("REMOTE_ADDR", "127.0.0.1")
