"""
PhishGuard AI — Subscription Webhook Processing
Processes lifecycle events idempotently from Razorpay and Stripe.
"""

import logging
from datetime import timedelta

from django.utils import timezone

from accounts.models import Invoice, Organization, PaymentEvent, Plan, Subscription

logger = logging.getLogger(__name__)


def process_razorpay_event(event_payload: dict) -> dict:
    """
    Processes an incoming Razorpay webhook payload idempotently.
    """
    event_id = event_payload.get("event_id") or event_payload.get("id") or f"rzp_{timezone.now().timestamp()}"
    event_type = event_payload.get("event", "payment.captured")

    # Idempotency check
    event_record, created = PaymentEvent.objects.get_or_create(
        event_id=event_id,
        gateway="razorpay",
        defaults={"event_type": event_type, "payload": event_payload},
    )
    if not created and event_record.processed:
        return {"status": "ignored", "reason": "duplicate_event", "event_id": event_id}

    payload_data = event_payload.get("payload", {})
    payment_entity = payload_data.get("payment", {}).get("entity", {})
    sub_entity = payload_data.get("subscription", {}).get("entity", {})

    notes = payment_entity.get("notes") or sub_entity.get("notes") or {}
    org_id = notes.get("org_id")
    plan_slug = notes.get("plan_slug", "pro")

    if not org_id:
        # If org_id is not present in notes, mark processed and return
        event_record.processed = True
        event_record.save()
        return {"status": "success", "reason": "no_org_associated"}

    try:
        org = Organization.objects.get(id=org_id)
        plan = Plan.objects.get(slug=plan_slug)
    except (Organization.DoesNotExist, Plan.DoesNotExist) as e:
        logger.error("Error processing Razorpay event: %s", e)
        return {"status": "error", "error": str(e)}

    # Handle event types
    if event_type in ["payment.captured", "subscription.charged", "order.paid"]:
        amount_paise = payment_entity.get("amount", int(plan.price_inr * 100))
        amount_inr = float(amount_paise) / 100.0
        payment_id = payment_entity.get("id", f"pay_rzp_{int(timezone.now().timestamp())}")

        # Update or create subscription
        subscription, _ = Subscription.objects.get_or_create(
            organization=org,
            defaults={"plan": plan, "gateway": Subscription.GATEWAY_RAZORPAY},
        )
        subscription.plan = plan
        subscription.status = Subscription.STATUS_ACTIVE
        subscription.gateway = Subscription.GATEWAY_RAZORPAY
        subscription.razorpay_subscription_id = sub_entity.get("id", "")
        subscription.current_period_end = timezone.now() + timedelta(days=30)
        subscription.save()

        # Create Invoice
        invoice_num = f"INV-RZP-{org.id}-{int(timezone.now().timestamp())}"
        Invoice.objects.create(
            organization=org,
            invoice_number=invoice_num,
            amount=amount_inr,
            currency="INR",
            gateway="razorpay",
            gateway_payment_id=payment_id,
            status=Invoice.STATUS_PAID,
            paid_at=timezone.now(),
        )

    elif event_type in ["subscription.halted", "payment.failed"]:
        try:
            subscription = org.subscription
            subscription.status = Subscription.STATUS_PAST_DUE
            subscription.save()
        except Subscription.DoesNotExist:
            pass

    elif event_type in ["subscription.cancelled"]:
        try:
            subscription = org.subscription
            subscription.status = Subscription.STATUS_CANCELLED
            subscription.save()
        except Subscription.DoesNotExist:
            pass

    event_record.processed = True
    event_record.save()
    return {"status": "success", "event_type": event_type, "org": org.name}


def process_stripe_event(event_payload: dict) -> dict:
    """
    Processes an incoming Stripe webhook payload idempotently.
    """
    event_id = event_payload.get("id", f"evt_stripe_{timezone.now().timestamp()}")
    event_type = event_payload.get("type", "checkout.session.completed")

    # Idempotency check
    event_record, created = PaymentEvent.objects.get_or_create(
        event_id=event_id,
        gateway="stripe",
        defaults={"event_type": event_type, "payload": event_payload},
    )
    if not created and event_record.processed:
        return {"status": "ignored", "reason": "duplicate_event", "event_id": event_id}

    data_object = event_payload.get("data", {}).get("object", {})
    metadata = data_object.get("metadata", {})
    org_id = metadata.get("org_id")
    plan_slug = metadata.get("plan_slug", "pro")

    if not org_id:
        event_record.processed = True
        event_record.save()
        return {"status": "success", "reason": "no_org_associated"}

    try:
        org = Organization.objects.get(id=org_id)
        plan = Plan.objects.get(slug=plan_slug)
    except (Organization.DoesNotExist, Plan.DoesNotExist) as e:
        logger.error("Error processing Stripe event: %s", e)
        return {"status": "error", "error": str(e)}

    if event_type in ["checkout.session.completed", "invoice.payment_succeeded", "customer.subscription.created"]:
        amount_cents = data_object.get("amount_total") or data_object.get("amount_paid", 900)
        amount_usd = float(amount_cents) / 100.0
        payment_id = data_object.get("payment_intent") or data_object.get("id", f"ch_stripe_{int(timezone.now().timestamp())}")

        subscription, _ = Subscription.objects.get_or_create(
            organization=org,
            defaults={"plan": plan, "gateway": Subscription.GATEWAY_STRIPE},
        )
        subscription.plan = plan
        subscription.status = Subscription.STATUS_ACTIVE
        subscription.gateway = Subscription.GATEWAY_STRIPE
        subscription.stripe_subscription_id = data_object.get("subscription", "")
        subscription.stripe_customer_id = data_object.get("customer", "")
        subscription.current_period_end = timezone.now() + timedelta(days=30)
        subscription.save()

        # Create Invoice
        invoice_num = f"INV-STRIPE-{org.id}-{int(timezone.now().timestamp())}"
        Invoice.objects.create(
            organization=org,
            invoice_number=invoice_num,
            amount=amount_usd,
            currency="USD",
            gateway="stripe",
            gateway_payment_id=payment_id,
            status=Invoice.STATUS_PAID,
            paid_at=timezone.now(),
        )

    elif event_type in ["invoice.payment_failed"]:
        try:
            subscription = org.subscription
            subscription.status = Subscription.STATUS_PAST_DUE
            subscription.save()
        except Subscription.DoesNotExist:
            pass

    elif event_type in ["customer.subscription.deleted"]:
        try:
            subscription = org.subscription
            subscription.status = Subscription.STATUS_CANCELLED
            subscription.save()
        except Subscription.DoesNotExist:
            pass

    event_record.processed = True
    event_record.save()
    return {"status": "success", "event_type": event_type, "org": org.name}
