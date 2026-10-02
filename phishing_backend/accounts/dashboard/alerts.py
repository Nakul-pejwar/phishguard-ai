"""
PhishGuard AI — Organization Threat Alert Dispatcher
Sends asynchronous or synchronous notifications to Slack/Teams webhooks when high-risk phishing incidents occur.
"""

import logging

import requests

logger = logging.getLogger(__name__)


def send_threat_alert(organization, domain: str, verdict: str, risk_level: str = "High", reported_by_email: str | None = None) -> bool:
    """
    Sends a security alert to the organization's configured Slack/Teams webhook.
    """
    try:
        policy = getattr(organization, "policy", None)
        if not policy or not policy.alert_webhook_url:
            return False

        webhook_url = policy.alert_webhook_url
        payload = {
            "text": f"🚨 *PhishGuard Security Alert* for *{organization.name}*\n"
                    f"• *Domain:* `{domain}`\n"
                    f"• *Verdict:* `{verdict.upper()}` ({risk_level})\n"
                    f"• *Reported By:* {reported_by_email or 'Automated Shield'}\n"
                    f"• *Action Taken:* Threat blocked by enterprise policy.",
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"🚨 *PhishGuard Threat Blocked* — *{organization.name}*\n"
                                f"A member encountered a malicious link:\n"
                                f"• *Target Domain:* `{domain}`\n"
                                f"• *Verdict:* `{verdict.upper()}`\n"
                                f"• *User:* {reported_by_email or 'Extension Shield'}",
                    },
                }
            ],
        }

        resp = requests.post(webhook_url, json=payload, timeout=3)
        return resp.status_code == 200
    except Exception as err:
        logger.warning("Failed to dispatch threat alert webhook: %s", err)
        return False
