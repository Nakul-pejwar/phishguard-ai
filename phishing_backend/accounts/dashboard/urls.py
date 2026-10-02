"""
PhishGuard AI — Team Dashboard URL Routing
"""

from django.urls import path

from .views import (
    AcceptInvitationView,
    ExportAuditCSVView,
    IncidentReportsListView,
    InviteMemberView,
    OrgMembersListView,
    OrgPolicyView,
    OverviewKPIView,
    ResolveIncidentReportView,
    ThreatTrendsView,
    TopThreatsView,
)

urlpatterns = [
    path("overview/", OverviewKPIView.as_view(), name="dashboard-overview"),
    path("trends/", ThreatTrendsView.as_view(), name="dashboard-trends"),
    path("top-threats/", TopThreatsView.as_view(), name="dashboard-top-threats"),
    path("policy/", OrgPolicyView.as_view(), name="dashboard-policy"),
    path("members/", OrgMembersListView.as_view(), name="dashboard-members"),
    path("members/invite/", InviteMemberView.as_view(), name="dashboard-invite-member"),
    path("members/accept-invite/", AcceptInvitationView.as_view(), name="dashboard-accept-invite"),
    path("reports/", IncidentReportsListView.as_view(), name="dashboard-reports"),
    path("reports/<int:pk>/resolve/", ResolveIncidentReportView.as_view(), name="dashboard-resolve-report"),
    path("export/csv/", ExportAuditCSVView.as_view(), name="dashboard-export-csv"),
]
