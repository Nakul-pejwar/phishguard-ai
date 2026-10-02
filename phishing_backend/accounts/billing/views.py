"""
PhishGuard AI — Billing & Subscription Views
"""

import json

from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from accounts.models import Membership, Plan, Subscription

from .gateways import RazorpayGateway, StripeGateway
from .serializers import PlanSerializer, SubscriptionDetailSerializer
from .webhooks import process_razorpay_event, process_stripe_event


class ListPlansView(APIView):
    """Lists available subscription plans."""
    permission_classes = [AllowAny]

    def get(self, request):
        plans = Plan.objects.filter(is_active=True).order_by("price_inr")
        serializer = PlanSerializer(plans, many=True)
        return Response({"plans": serializer.data})


class CreateCheckoutSessionView(APIView):
    """
    Initiates a checkout session for a selected plan via Razorpay or Stripe.
    """
    permission_classes = [IsAuthenticated]

    def post(self, request):
        membership = Membership.objects.filter(user=request.user).select_related("organization").first()
        if not membership:
            return Response({"error": "No organization associated with user."}, status=status.HTTP_400_BAD_REQUEST)

        plan_slug = request.data.get("plan_slug", "pro").lower()
        gateway = request.data.get("gateway", "razorpay").lower()

        try:
            plan = Plan.objects.get(slug=plan_slug, is_active=True)
        except Plan.DoesNotExist:
            return Response({"error": f"Plan '{plan_slug}' not found."}, status=status.HTTP_404_NOT_FOUND)

        org = membership.organization

        if gateway == "stripe":
            stripe_gw = StripeGateway()
            # Approx USD conversion: INR / 85 or standard price
            amount_usd = 9.00 if plan_slug == "pro" else (39.00 if plan_slug == "team" else 199.00)
            success_url = request.data.get("success_url", "https://phishguard.ai/billing/success")
            cancel_url = request.data.get("cancel_url", "https://phishguard.ai/billing/cancel")

            session_data = stripe_gw.create_checkout_session(
                amount_usd=amount_usd,
                org_id=org.id,
                plan_slug=plan.slug,
                success_url=success_url,
                cancel_url=cancel_url,
            )
            return Response(session_data, status=status.HTTP_200_OK)

        else:
            # Default to Razorpay
            rzp_gw = RazorpayGateway()
            order_data = rzp_gw.create_checkout_order(
                amount_inr=float(plan.price_inr),
                org_id=org.id,
                plan_slug=plan.slug,
            )
            return Response(order_data, status=status.HTTP_200_OK)


class RazorpayWebhookView(APIView):
    """Handles incoming Razorpay Webhook events."""
    permission_classes = [AllowAny]
    authentication_classes = []

    def post(self, request):
        signature = request.headers.get("X-Razorpay-Signature", "")
        raw_body = request.body

        gateway = RazorpayGateway()
        if not gateway.verify_webhook_signature(raw_body, signature):
            return Response({"error": "Invalid Razorpay signature"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            payload = json.loads(raw_body.decode("utf-8"))
        except Exception:
            return Response({"error": "Invalid JSON payload"}, status=status.HTTP_400_BAD_REQUEST)

        result = process_razorpay_event(payload)
        return Response(result, status=status.HTTP_200_OK)


class StripeWebhookView(APIView):
    """Handles incoming Stripe Webhook events."""
    permission_classes = [AllowAny]
    authentication_classes = []

    def post(self, request):
        sig_header = request.headers.get("Stripe-Signature", "")
        raw_body = request.body

        gateway = StripeGateway()
        if not gateway.verify_webhook_signature(raw_body, sig_header):
            return Response({"error": "Invalid Stripe signature"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            payload = json.loads(raw_body.decode("utf-8"))
        except Exception:
            return Response({"error": "Invalid JSON payload"}, status=status.HTTP_400_BAD_REQUEST)

        result = process_stripe_event(payload)
        return Response(result, status=status.HTTP_200_OK)


class SubscriptionDetailView(APIView):
    """Returns current active subscription, plan, features, and past invoices."""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        membership = Membership.objects.filter(user=request.user).select_related("organization").first()
        if not membership:
            return Response({"error": "No organization found."}, status=status.HTTP_404_NOT_FOUND)

        org = membership.organization
        subscription, _ = Subscription.objects.get_or_create(
            organization=org,
            defaults={"plan": Plan.get_default_plan()},
        )
        serializer = SubscriptionDetailSerializer(subscription)
        return Response(serializer.data, status=status.HTTP_200_OK)


class CancelSubscriptionView(APIView):
    """Cancels active subscription at period end."""
    permission_classes = [IsAuthenticated]

    def post(self, request):
        membership = Membership.objects.filter(
            user=request.user,
            role__in=[Membership.ROLE_ADMIN, Membership.ROLE_OWNER],
        ).select_related("organization").first()

        if not membership:
            return Response(
                {"error": "Only organization admins or owners can cancel subscriptions."},
                status=status.HTTP_403_FORBIDDEN,
            )

        org = membership.organization
        try:
            subscription = org.subscription
            subscription.status = Subscription.STATUS_CANCELLED
            subscription.save(update_fields=["status", "updated_at"])
            return Response({"status": "Subscription cancelled successfully."})
        except Subscription.DoesNotExist:
            return Response({"error": "No active subscription found."}, status=status.HTTP_404_NOT_FOUND)
