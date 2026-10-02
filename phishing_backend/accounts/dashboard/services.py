"""
PhishGuard AI — Dashboard Analytics & Export Services
Strictly tenant-isolated data operations for enterprise visibility.
"""

import csv
import io
from datetime import timedelta

from django.db.models import Count
from django.utils import timezone

from accounts.models import IncidentReport, Membership, Organization, UsageLog


class DashboardAnalyticsService:
    """Computes real-time telemetry, KPI summaries, and threat trends for an organization."""

    @staticmethod
    def get_overview_kpis(org: Organization) -> dict:
        now = timezone.now()
        thirty_days_ago = now - timedelta(days=30)

        logs_qs = UsageLog.objects.filter(organization=org, created_at__gte=thirty_days_ago)

        total_scans = logs_qs.count()
        phishing_hits = logs_qs.filter(verdict__in=["phishing", "suspicious"]).count()
        safe_scans = logs_qs.filter(verdict="safe").count()

        block_rate = round((phishing_hits / total_scans * 100), 1) if total_scans > 0 else 0.0
        active_seats = Membership.objects.filter(organization=org).count()
        pending_incidents = IncidentReport.objects.filter(organization=org, status="pending").count()

        return {
            "total_scans_30d": total_scans,
            "blocked_threats_30d": phishing_hits,
            "safe_scans_30d": safe_scans,
            "threat_block_rate_pct": block_rate,
            "active_members_count": active_seats,
            "pending_incident_reviews": pending_incidents,
        }

    @staticmethod
    def get_threat_trends_30d(org: Organization) -> list[dict]:
        now = timezone.now()
        trends = []

        for i in range(29, -1, -1):
            day_start = (now - timedelta(days=i)).replace(hour=0, minute=0, second=0, microsecond=0)
            day_end = day_start + timedelta(days=1)

            day_logs = UsageLog.objects.filter(organization=org, created_at__gte=day_start, created_at__lt=day_end)
            total = day_logs.count()
            phishing = day_logs.filter(verdict__in=["phishing", "suspicious"]).count()
            safe = day_logs.filter(verdict="safe").count()

            trends.append({
                "date": day_start.strftime("%Y-%m-%d"),
                "total_scans": total,
                "phishing_blocked": phishing,
                "safe_scans": safe,
            })

        return trends

    @staticmethod
    def get_top_threats(org: Organization, limit: int = 10) -> list[dict]:
        """Returns top blocked domains for the organization."""
        return list(
            UsageLog.objects.filter(organization=org, verdict__in=["phishing", "suspicious"])
            .values("domain")
            .annotate(hit_count=Count("id"))
            .order_by("-hit_count")[:limit]
        )

    @staticmethod
    def get_most_targeted_users(org: Organization, limit: int = 5) -> list[dict]:
        """Returns members facing the highest number of phishing link encounters."""
        return list(
            UsageLog.objects.filter(organization=org, verdict__in=["phishing", "suspicious"], user__isnull=False)
            .values("user__email", "user__first_name", "user__last_name")
            .annotate(threats_blocked=Count("id"))
            .order_by("-threats_blocked")[:limit]
        )


class ReportExportService:
    """Generates privacy-compliant audit CSV exports."""

    @staticmethod
    def export_usage_logs_csv(org: Organization) -> io.StringIO:
        output = io.StringIO()
        writer = csv.writer(output)

        # Header row
        writer.writerow([
            "Timestamp (UTC)",
            "User Email",
            "Domain",
            "URL SHA-256 Hash",
            "Safety Verdict",
            "Risk Level",
            "Client IP",
        ])

        logs = UsageLog.objects.filter(organization=org).select_related("user").order_by("-created_at")[:5000]

        for log in logs:
            writer.writerow([
                log.created_at.strftime("%Y-%m-%d %H:%M:%S"),
                log.user.email if log.user else "Anonymous/API Key",
                log.domain,
                log.url_hash,
                log.verdict,
                log.risk_level,
                log.ip_address or "N/A",
            ])

        output.seek(0)
        return output
