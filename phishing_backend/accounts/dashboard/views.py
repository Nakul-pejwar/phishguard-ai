"""
PhishGuard AI — Team Dashboard & Enterprise Reporting Views
All endpoints enforce strict organization-level multi-tenancy.
"""

import hashlib

from django.http import HttpResponse
from django.utils import timezone
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from accounts.models import IncidentReport, Membership, OrgInvitation, OrgPolicy

from .serializers import (
    IncidentReportSerializer,
    MembershipDetailSerializer,
    OrgInvitationSerializer,
    OrgPolicySerializer,
)
from .services import DashboardAnalyticsService, ReportExportService


class BaseOrgDashboardView(APIView):
    """Base view extracting and verifying the authenticated user's organization."""
    permission_classes = [IsAuthenticated]

    def get_user_membership(self, request) -> Membership | None:
        return Membership.objects.filter(user=request.user).select_related("organization").first()


class OverviewKPIView(BaseOrgDashboardView):
    """Returns top KPI cards for the organization dashboard."""

    def get(self, request):
        membership = self.get_user_membership(request)
        if not membership:
            return Response({"error": "User does not belong to any organization."}, status=status.HTTP_404_NOT_FOUND)

        kpis = DashboardAnalyticsService.get_overview_kpis(membership.organization)
        return Response(kpis, status=status.HTTP_200_OK)


class ThreatTrendsView(BaseOrgDashboardView):
    """Returns 30-day time series of total vs blocked threats."""

    def get(self, request):
        membership = self.get_user_membership(request)
        if not membership:
            return Response({"error": "No organization found."}, status=status.HTTP_404_NOT_FOUND)

        trends = DashboardAnalyticsService.get_threat_trends_30d(membership.organization)
        return Response({"trends": trends}, status=status.HTTP_200_OK)


class TopThreatsView(BaseOrgDashboardView):
    """Returns top blocked domains and most targeted employees."""

    def get(self, request):
        membership = self.get_user_membership(request)
        if not membership:
            return Response({"error": "No organization found."}, status=status.HTTP_404_NOT_FOUND)

        top_domains = DashboardAnalyticsService.get_top_threats(membership.organization)
        targeted_users = DashboardAnalyticsService.get_most_targeted_users(membership.organization)
        return Response({
            "top_domains": top_domains,
            "most_targeted_members": targeted_users,
        }, status=status.HTTP_200_OK)


class OrgPolicyView(BaseOrgDashboardView):
    """Retrieves or updates the organization security policy."""

    def get(self, request):
        membership = self.get_user_membership(request)
        if not membership:
            return Response({"error": "No organization found."}, status=status.HTTP_404_NOT_FOUND)

        policy, _ = OrgPolicy.objects.get_or_create(organization=membership.organization)
        serializer = OrgPolicySerializer(policy)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def put(self, request):
        membership = self.get_user_membership(request)
        if not membership or membership.role not in [Membership.ROLE_ADMIN, Membership.ROLE_OWNER]:
            return Response({"error": "Admin permission required to update policy."}, status=status.HTTP_403_FORBIDDEN)

        policy, _ = OrgPolicy.objects.get_or_create(organization=membership.organization)
        serializer = OrgPolicySerializer(policy, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class OrgMembersListView(BaseOrgDashboardView):
    """Lists current organization members and pending invitations."""

    def get(self, request):
        membership = self.get_user_membership(request)
        if not membership:
            return Response({"error": "No organization found."}, status=status.HTTP_404_NOT_FOUND)

        members = Membership.objects.filter(organization=membership.organization).select_related("user")
        invites = OrgInvitation.objects.filter(organization=membership.organization, accepted_at__isnull=True)

        return Response({
            "members": MembershipDetailSerializer(members, many=True).data,
            "pending_invitations": OrgInvitationSerializer(invites, many=True).data,
        }, status=status.HTTP_200_OK)


class InviteMemberView(BaseOrgDashboardView):
    """Invites a new member by email."""

    def post(self, request):
        membership = self.get_user_membership(request)
        if not membership or membership.role not in [Membership.ROLE_ADMIN, Membership.ROLE_OWNER]:
            return Response({"error": "Admin permission required to invite members."}, status=status.HTTP_403_FORBIDDEN)

        email = request.data.get("email", "").strip()
        role = request.data.get("role", Membership.ROLE_MEMBER)

        if not email:
            return Response({"error": "Email is required."}, status=status.HTTP_400_BAD_REQUEST)

        # Check seat limits against plan
        active_plan = membership.organization.get_active_plan()
        current_seats = Membership.objects.filter(organization=membership.organization).count()
        allowed_seats = active_plan.features.get("team_seats", 1)

        if allowed_seats != -1 and current_seats >= allowed_seats:
            return Response(
                {"error": f"Seat limit reached ({current_seats}/{allowed_seats}). Please upgrade your plan."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        invite = OrgInvitation.create_invite(
            organization=membership.organization,
            email=email,
            role=role,
            invited_by=request.user,
        )
        serializer = OrgInvitationSerializer(invite)
        return Response(serializer.data, status=status.HTTP_201_CREATED)


class AcceptInvitationView(APIView):
    """Accepts a tokenized invitation and adds the user to the organization."""
    permission_classes = [IsAuthenticated]

    def post(self, request):
        token = request.data.get("token", "").strip()
        if not token:
            return Response({"error": "Invite token is required."}, status=status.HTTP_400_BAD_REQUEST)

        invite = OrgInvitation.objects.filter(token=token).select_related("organization").first()
        if not invite or not invite.is_valid:
            return Response({"error": "Invitation is invalid or has expired."}, status=status.HTTP_400_BAD_REQUEST)

        # Create or update membership
        membership, _ = Membership.objects.get_or_create(
            user=request.user,
            organization=invite.organization,
            defaults={"role": invite.role},
        )
        membership.role = invite.role
        membership.save()

        invite.accepted_at = timezone.now()
        invite.save(update_fields=["accepted_at"])

        return Response({
            "status": "success",
            "message": f"Successfully joined {invite.organization.name} as {invite.role}.",
        }, status=status.HTTP_200_OK)


class IncidentReportsListView(BaseOrgDashboardView):
    """Lists and creates employee threat / false-positive incident reports."""

    def get(self, request):
        membership = self.get_user_membership(request)
        if not membership:
            return Response({"error": "No organization found."}, status=status.HTTP_404_NOT_FOUND)

        reports = IncidentReport.objects.filter(organization=membership.organization).order_by("-created_at")[:100]
        serializer = IncidentReportSerializer(reports, many=True)
        return Response({"reports": serializer.data}, status=status.HTTP_200_OK)

    def post(self, request):
        membership = self.get_user_membership(request)
        if not membership:
            return Response({"error": "No organization found."}, status=status.HTTP_404_NOT_FOUND)

        url = request.data.get("url", "").strip()
        domain = request.data.get("domain", "").strip()
        report_type = request.data.get("report_type", IncidentReport.TYPE_PHISHING)
        notes = request.data.get("notes", "")

        if not domain and url:
            try:
                from urllib.parse import urlparse
                domain = urlparse(url).netloc or url
            except Exception:
                domain = url

        url_hash = hashlib.sha256(url.encode("utf-8")).hexdigest() if url else ""

        report = IncidentReport.objects.create(
            organization=membership.organization,
            reported_by=request.user,
            domain=domain,
            url_hash=url_hash,
            report_type=report_type,
            notes=notes,
        )
        serializer = IncidentReportSerializer(report)
        return Response(serializer.data, status=status.HTTP_201_CREATED)


class ResolveIncidentReportView(BaseOrgDashboardView):
    """Resolves an incident report as confirmed phishing or false positive."""

    def patch(self, request, pk: int):
        membership = self.get_user_membership(request)
        if not membership or membership.role not in [Membership.ROLE_ADMIN, Membership.ROLE_OWNER]:
            return Response({"error": "Admin permission required to resolve reports."}, status=status.HTTP_403_FORBIDDEN)

        report = IncidentReport.objects.filter(id=pk, organization=membership.organization).first()
        if not report:
            return Response({"error": "Incident report not found."}, status=status.HTTP_404_NOT_FOUND)

        new_status = request.data.get("status")
        if new_status not in [IncidentReport.STATUS_CONFIRMED, IncidentReport.STATUS_FALSE_POSITIVE, IncidentReport.STATUS_DISMISSED]:
            return Response({"error": f"Invalid status '{new_status}'."}, status=status.HTTP_400_BAD_REQUEST)

        report.status = new_status
        report.resolved_by = request.user
        report.resolved_at = timezone.now()
        report.save()

        # If marked as false positive, auto-add to policy allowlist if requested
        if new_status == IncidentReport.STATUS_FALSE_POSITIVE and request.data.get("add_to_allowlist"):
            policy, _ = OrgPolicy.objects.get_or_create(organization=membership.organization)
            allowlist = list(policy.custom_allowlist or [])
            if report.domain not in allowlist:
                allowlist.append(report.domain)
                policy.custom_allowlist = allowlist
                policy.save()

        serializer = IncidentReportSerializer(report)
        return Response(serializer.data, status=status.HTTP_200_OK)


class ExportAuditCSVView(BaseOrgDashboardView):
    """Streams a privacy-compliant CSV audit export."""

    def get(self, request):
        membership = self.get_user_membership(request)
        if not membership:
            return Response({"error": "No organization found."}, status=status.HTTP_404_NOT_FOUND)

        csv_file = ReportExportService.export_usage_logs_csv(membership.organization)
        response = HttpResponse(csv_file.getvalue(), content_type="text/csv")
        response["Content-Disposition"] = f'attachment; filename="phishguard_audit_{membership.organization.slug}.csv"'
        return response
