"""
PhishGuard AI — Billing URL Routing
"""

from django.urls import path

from .views import (
    CancelSubscriptionView,
    CreateCheckoutSessionView,
    ListPlansView,
    RazorpayWebhookView,
    StripeWebhookView,
    SubscriptionDetailView,
)

urlpatterns = [
    path("plans/", ListPlansView.as_view(), name="billing-plans"),
    path("checkout/", CreateCheckoutSessionView.as_view(), name="billing-checkout"),
    path("subscription/", SubscriptionDetailView.as_view(), name="billing-subscription"),
    path("cancel/", CancelSubscriptionView.as_view(), name="billing-cancel"),
    path("webhooks/razorpay/", RazorpayWebhookView.as_view(), name="billing-webhook-razorpay"),
    path("webhooks/stripe/", StripeWebhookView.as_view(), name="billing-webhook-stripe"),
]
