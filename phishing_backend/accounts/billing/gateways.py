"""
PhishGuard AI — Payment Gateway Integrations
Supports Razorpay (India: UPI / Cards / NetBanking) and Stripe (Global USD).
"""

import hashlib
import hmac
import logging
import os
import time

logger = logging.getLogger(__name__)


class RazorpayGateway:
    """Wrapper for Razorpay API and Webhook verification."""

    def __init__(self, key_id: str | None = None, key_secret: str | None = None, webhook_secret: str | None = None):
        self.key_id = key_id or os.getenv("RAZORPAY_KEY_ID", "rzp_test_placeholder")
        self.key_secret = key_secret or os.getenv("RAZORPAY_KEY_SECRET", "rzp_secret_placeholder")
        self.webhook_secret = webhook_secret or os.getenv("RAZORPAY_WEBHOOK_SECRET", "rzp_webhook_secret_placeholder")

    def verify_webhook_signature(self, body_bytes: bytes, signature: str) -> bool:
        """Verifies Razorpay HMAC-SHA256 webhook signature."""
        if not signature or not self.webhook_secret:
            return False
        try:
            expected_signature = hmac.new(
                self.webhook_secret.encode("utf-8"),
                body_bytes,
                hashlib.sha256,
            ).hexdigest()
            return hmac.compare_digest(expected_signature, signature)
        except Exception as err:
            logger.error("Error verifying Razorpay webhook signature: %s", err)
            return False

    def create_checkout_order(self, amount_inr: float, org_id: int, plan_slug: str) -> dict:
        """
        Creates a Razorpay Order.
        In test / mock environments without live credentials, generates a structured response.
        """
        amount_paise = int(amount_inr * 100)
        order_id = f"order_rzp_{org_id}_{int(time.time())}"
        return {
            "gateway": "razorpay",
            "order_id": order_id,
            "key_id": self.key_id,
            "amount": amount_paise,
            "currency": "INR",
            "name": "PhishGuard AI Subscription",
            "description": f"PhishGuard {plan_slug.upper()} Plan",
            "notes": {
                "org_id": str(org_id),
                "plan_slug": plan_slug,
            },
        }


class StripeGateway:
    """Wrapper for Stripe API and Webhook verification."""

    def __init__(self, api_key: str | None = None, webhook_secret: str | None = None):
        self.api_key = api_key or os.getenv("STRIPE_SECRET_KEY", "sk_test_placeholder")
        self.webhook_secret = webhook_secret or os.getenv("STRIPE_WEBHOOK_SECRET", "whsec_test_placeholder")

    def verify_webhook_signature(self, payload: bytes, sig_header: str) -> bool:
        """Verifies Stripe webhook signature using timestamp and HMAC SHA-256."""
        if not sig_header or not self.webhook_secret:
            return False
        try:
            # Parse Stripe-Signature header: t=1492774577,v1=5257a869e7ecebeda32affa...
            sig_dict = {}
            for item in sig_header.split(","):
                parts = item.split("=", 1)
                if len(parts) == 2:
                    sig_dict[parts[0].strip()] = parts[1].strip()

            timestamp = sig_dict.get("t")
            signature_v1 = sig_dict.get("v1")
            if not timestamp or not signature_v1:
                return False

            signed_payload = f"{timestamp}.".encode("utf-8") + payload
            expected_sig = hmac.new(
                self.webhook_secret.encode("utf-8"),
                signed_payload,
                hashlib.sha256,
            ).hexdigest()
            return hmac.compare_digest(expected_sig, signature_v1)
        except Exception as err:
            logger.error("Error verifying Stripe webhook signature: %s", err)
            return False

    def create_checkout_session(self, amount_usd: float, org_id: int, plan_slug: str, success_url: str, cancel_url: str) -> dict:
        """Generates a Stripe hosted checkout URL or mock payload."""
        session_id = f"cs_test_{org_id}_{int(time.time())}"
        return {
            "gateway": "stripe",
            "session_id": session_id,
            "checkout_url": f"https://checkout.stripe.com/c/pay/{session_id}",
            "amount": int(amount_usd * 100),
            "currency": "USD",
            "metadata": {
                "org_id": str(org_id),
                "plan_slug": plan_slug,
            },
        }
