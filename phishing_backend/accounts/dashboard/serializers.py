"""
PhishGuard AI — Team Dashboard Serializers
"""

from django.contrib.auth import get_user_model
from rest_framework import serializers

from accounts.models import IncidentReport, Membership, OrgInvitation, OrgPolicy

User = get_user_model()


class OrgPolicySerializer(serializers.ModelSerializer):
    class Meta:
        model = OrgPolicy
        fields = [
            "mode",
            "custom_allowlist",
            "custom_blocklist",
            "enforce_extension",
            "alert_webhook_url",
            "alert_email",
            "updated_at",
        ]


class OrgInvitationSerializer(serializers.ModelSerializer):
    invited_by_email = serializers.SerializerMethodField()

    class Meta:
        model = OrgInvitation
        fields = [
            "id",
            "email",
            "role",
            "token",
            "invited_by_email",
            "expires_at",
            "accepted_at",
            "created_at",
        ]
        read_only_fields = ["id", "token", "invited_by_email", "expires_at", "accepted_at", "created_at"]

    def get_invited_by_email(self, obj):
        return obj.invited_by.email if obj.invited_by else None


class MemberUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["id", "username", "email", "first_name", "last_name", "date_joined"]


class MembershipDetailSerializer(serializers.ModelSerializer):
    user = MemberUserSerializer(read_only=True)

    class Meta:
        model = Membership
        fields = ["id", "user", "role", "created_at"]


class IncidentReportSerializer(serializers.ModelSerializer):
    reported_by_email = serializers.SerializerMethodField()
    resolved_by_email = serializers.SerializerMethodField()

    class Meta:
        model = IncidentReport
        fields = [
            "id",
            "domain",
            "url_hash",
            "report_type",
            "status",
            "notes",
            "reported_by_email",
            "resolved_by_email",
            "resolved_at",
            "created_at",
        ]
        read_only_fields = ["id", "url_hash", "reported_by_email", "resolved_by_email", "resolved_at", "created_at"]

    def get_reported_by_email(self, obj):
        return obj.reported_by.email if obj.reported_by else "Extension User"

    def get_resolved_by_email(self, obj):
        return obj.resolved_by.email if obj.resolved_by else None
