"""
PhishGuard AI — Billing Serializers
"""

from rest_framework import serializers

from accounts.models import Invoice, Plan, Subscription


class PlanSerializer(serializers.ModelSerializer):
    class Meta:
        model = Plan
        fields = ["id", "name", "slug", "daily_scan_limit", "features", "price_inr", "is_active"]


class InvoiceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Invoice
        fields = [
            "id",
            "invoice_number",
            "amount",
            "currency",
            "gateway",
            "status",
            "gstin",
            "paid_at",
            "created_at",
        ]


class SubscriptionDetailSerializer(serializers.ModelSerializer):
    plan = PlanSerializer(read_only=True)
    invoices = serializers.SerializerMethodField()

    class Meta:
        model = Subscription
        fields = [
            "id",
            "plan",
            "status",
            "gateway",
            "current_period_end",
            "created_at",
            "invoices",
        ]

    def get_invoices(self, obj):
        invoices = Invoice.objects.filter(organization=obj.organization)[:10]
        return InvoiceSerializer(invoices, many=True).data
