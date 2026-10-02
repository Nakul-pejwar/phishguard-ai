"""
Unit & integration tests for Phase 5 Billing (Razorpay + Stripe + Invoices + Idempotency).
"""

import hashlib
import hmac
import time

import pytest
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient

from accounts.billing.gateways import RazorpayGateway, StripeGateway
from accounts.billing.permissions import HasFeaturePermission
from accounts.billing.webhooks import process_razorpay_event, process_stripe_event
from accounts.models import Invoice, Membership, Organization, Plan, Subscription

User = get_user_model()


@pytest.fixture
def auth_user():
    return User.objects.create_user(
        username="billing_tester",
        email="billing_tester@example.com",
        password="TestPassword123!",
    )


@pytest.fixture
def billing_org(auth_user):
    org = Organization.objects.create(name="Fintech Corp", slug="fintech-corp")
    Membership.objects.create(user=auth_user, organization=org, role=Membership.ROLE_OWNER)

    # Setup plans
    Plan.objects.get_or_create(
        slug="free",
        defaults={"name": "Free", "daily_scan_limit": 20, "price_inr": 0.00, "features": {"api_access": False}},
    )
    Plan.objects.get_or_create(
        slug="pro",
        defaults={
            "name": "Pro",
            "daily_scan_limit": 500,
            "price_inr": 499.00,
            "features": {"api_access": True, "team_seats": 1, "domain_cache": True},
        },
    )
    return org


@pytest.mark.django_db
def test_razorpay_gateway_signature_verification():
    secret = "rzp_webhook_secret_key_123"
    gateway = RazorpayGateway(webhook_secret=secret)

    payload = b'{"event": "payment.captured", "id": "evt_123"}'
    valid_signature = hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()

    assert gateway.verify_webhook_signature(payload, valid_signature) is True
    assert gateway.verify_webhook_signature(payload, "invalid_tampered_sig") is False
    assert gateway.verify_webhook_signature(payload, "") is False


@pytest.mark.django_db
def test_stripe_gateway_signature_verification():
    secret = "whsec_test_stripe_secret_456"
    gateway = StripeGateway(webhook_secret=secret)

    payload = b'{"type": "checkout.session.completed", "id": "evt_stripe_1"}'
    timestamp = str(int(time.time()))
    signed_payload = f"{timestamp}.".encode("utf-8") + payload
    valid_sig = hmac.new(secret.encode("utf-8"), signed_payload, hashlib.sha256).hexdigest()
    sig_header = f"t={timestamp},v1={valid_sig}"

    assert gateway.verify_webhook_signature(payload, sig_header) is True
    assert gateway.verify_webhook_signature(payload, f"t={timestamp},v1=wrong_sig") is False
    assert gateway.verify_webhook_signature(payload, "") is False


@pytest.mark.django_db
def test_razorpay_webhook_processing_and_idempotency(billing_org):
    pro_plan = Plan.objects.get(slug="pro")
    event_payload = {
        "event_id": "evt_rzp_test_001",
        "event": "payment.captured",
        "payload": {
            "payment": {
                "entity": {
                    "id": "pay_test_999",
                    "amount": 49900,
                    "currency": "INR",
                    "notes": {
                        "org_id": str(billing_org.id),
                        "plan_slug": pro_plan.slug,
                    },
                }
            }
        },
    }

    # First event delivery
    res1 = process_razorpay_event(event_payload)
    assert res1["status"] == "success"
    assert res1["event_type"] == "payment.captured"

    # Verify subscription activated and invoice created
    sub = billing_org.subscription
    assert sub.status == Subscription.STATUS_ACTIVE
    assert sub.plan == pro_plan
    assert sub.gateway == Subscription.GATEWAY_RAZORPAY

    invoices = Invoice.objects.filter(organization=billing_org)
    assert invoices.count() == 1
    assert invoices.first().amount == 499.00

    # Second event delivery with same event_id (Idempotency verification)
    res2 = process_razorpay_event(event_payload)
    assert res2["status"] == "ignored"
    assert res2["reason"] == "duplicate_event"

    # Invoices count must still be 1 (No duplicate invoice created)
    assert Invoice.objects.filter(organization=billing_org).count() == 1


@pytest.mark.django_db
def test_stripe_webhook_processing_and_lifecycle(billing_org):
    pro_plan = Plan.objects.get(slug="pro")
    event_payload = {
        "id": "evt_stripe_test_002",
        "type": "checkout.session.completed",
        "data": {
            "object": {
                "id": "cs_test_session_123",
                "payment_intent": "pi_test_intent_456",
                "amount_total": 900,
                "customer": "cus_test_789",
                "subscription": "sub_test_stripe_001",
                "metadata": {
                    "org_id": str(billing_org.id),
                    "plan_slug": pro_plan.slug,
                },
            }
        },
    }

    # 1. Successful checkout
    res1 = process_stripe_event(event_payload)
    assert res1["status"] == "success"

    sub = billing_org.subscription
    assert sub.status == Subscription.STATUS_ACTIVE
    assert sub.gateway == Subscription.GATEWAY_STRIPE
    assert sub.stripe_subscription_id == "sub_test_stripe_001"

    # 2. Failed payment event (status becomes past_due)
    fail_event = {
        "id": "evt_stripe_fail_003",
        "type": "invoice.payment_failed",
        "data": {"object": {"metadata": {"org_id": str(billing_org.id)}}},
    }
    process_stripe_event(fail_event)
    sub.refresh_from_db()
    assert sub.status == Subscription.STATUS_PAST_DUE

    # 3. Subscription deleted event (status becomes cancelled)
    del_event = {
        "id": "evt_stripe_del_004",
        "type": "customer.subscription.deleted",
        "data": {"object": {"metadata": {"org_id": str(billing_org.id)}}},
    }
    process_stripe_event(del_event)
    sub.refresh_from_db()
    assert sub.status == Subscription.STATUS_CANCELLED


@pytest.mark.django_db
def test_billing_checkout_and_subscription_api(auth_user, billing_org):
    client = APIClient()
    client.force_authenticate(user=auth_user)

    # 1. List Plans
    resp_plans = client.get("/api/billing/plans/")
    assert resp_plans.status_code == 200
    assert len(resp_plans.data["plans"]) >= 2

    # 2. Initiate Razorpay Checkout
    resp_rzp = client.post("/api/billing/checkout/", {"plan_slug": "pro", "gateway": "razorpay"})
    assert resp_rzp.status_code == 200
    assert resp_rzp.data["gateway"] == "razorpay"
    assert "order_id" in resp_rzp.data

    # 3. Initiate Stripe Checkout
    resp_stripe = client.post("/api/billing/checkout/", {"plan_slug": "pro", "gateway": "stripe"})
    assert resp_stripe.status_code == 200
    assert resp_stripe.data["gateway"] == "stripe"
    assert "checkout_url" in resp_stripe.data

    # 4. Get Subscription Details
    resp_sub = client.get("/api/billing/subscription/")
    assert resp_sub.status_code == 200
    assert "plan" in resp_sub.data
    assert "invoices" in resp_sub.data

    # 5. Cancel Subscription
    resp_cancel = client.post("/api/billing/cancel/")
    assert resp_cancel.status_code == 200
    assert resp_cancel.data["status"] == "Subscription cancelled successfully."


@pytest.mark.django_db
def test_plan_feature_flag_permissions(auth_user, billing_org):
    free_plan = Plan.objects.get(slug="free")
    pro_plan = Plan.objects.get(slug="pro")

    # Set free plan (api_access = False)
    sub, _ = Subscription.objects.get_or_create(
        organization=billing_org,
        defaults={"plan": free_plan},
    )
    sub.plan = free_plan
    sub.save()

    perm_checker = HasFeaturePermission("api_access")()

    class MockRequest:
        def __init__(self, user):
            self.user = user

    req = MockRequest(auth_user)
    assert perm_checker.has_permission(req, None) is False

    # Upgrade to Pro (api_access = True)
    sub.plan = pro_plan
    sub.save()
    assert perm_checker.has_permission(req, None) is True
