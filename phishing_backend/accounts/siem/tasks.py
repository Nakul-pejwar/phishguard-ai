import json
import logging
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from celery import shared_task
from django.utils import timezone

from accounts.models import Organization, SIEMConfiguration

logger = logging.getLogger(__name__)


def build_siem_payload(siem_type: str, incident_data: dict, org_name: str) -> tuple[dict, dict]:
    """
    Builds structured payload and headers for the target SIEM provider.
    """
    headers = {"Content-Type": "application/json"}
    now_iso = timezone.now().isoformat()

    if siem_type == SIEMConfiguration.TYPE_SPLUNK:
        payload = {
            "time": int(timezone.now().timestamp()),
            "host": "phishguard-cloud",
            "source": "phishguard_threat_engine",
            "sourcetype": "phishguard:security:incident",
            "event": {
                "organization": org_name,
                "event_type": "phishing_threat_detected",
                "timestamp": now_iso,
                **incident_data,
            },
        }
    elif siem_type == SIEMConfiguration.TYPE_DATADOG:
        payload = {
            "ddsource": "phishguard",
            "service": "phishguard-ai",
            "ddtags": f"org:{org_name},env:production",
            "message": f"PhishGuard Security Alert: {incident_data.get('domain', 'Unknown Domain')}",
            "incident": incident_data,
            "timestamp": now_iso,
        }
    else:
        # Microsoft Sentinel / Generic Webhook format (CEF-compatible JSON)
        payload = {
            "version": "1.0",
            "event_type": "phishguard.security.threat",
            "organization": org_name,
            "timestamp": now_iso,
            "severity": incident_data.get("risk_level", "high"),
            "threat_details": incident_data,
        }

    return payload, headers


@shared_task(bind=True, max_retries=3, default_retry_delay=60)
def forward_threat_to_siem(self, incident_data: dict, organization_id: int):
    """
    Asynchronously streams threat detection events to configured enterprise SIEM endpoints.
    """
    try:
        org = Organization.objects.get(id=organization_id)
        config = getattr(org, "siem_config", None)
        if not config or not config.is_active or not config.endpoint_url:
            return "SIEM forwarding disabled or not configured."

        # Severity filter check
        min_sev = config.min_severity.lower()
        event_sev = str(incident_data.get("risk_level", "high")).lower()
        if min_sev == "high" and "high" not in event_sev and "critical" not in event_sev:
            return "Event skipped due to SIEM minimum severity filter."

        payload, headers = build_siem_payload(config.siem_type, incident_data, org.name)

        if config.auth_token:
            if config.siem_type == SIEMConfiguration.TYPE_SPLUNK:
                headers["Authorization"] = f"Splunk {config.auth_token}"
            else:
                header_name = config.auth_header_name or "Authorization"
                token_val = config.auth_token if " " in config.auth_token else f"Bearer {config.auth_token}"
                headers[header_name] = token_val

        body_bytes = json.dumps(payload).encode("utf-8")
        req = Request(config.endpoint_url, data=body_bytes, headers=headers, method="POST")

        with urlopen(req, timeout=10) as resp:
            resp_code = resp.getcode()
            if 200 <= resp_code < 300:
                config.last_event_sent_at = timezone.now()
                config.save(update_fields=["last_event_sent_at"])
                return f"Successfully delivered event to {config.siem_type} (HTTP {resp_code})"

    except (HTTPError, URLError) as exc:
        logger.warning(f"SIEM delivery failed for Org {organization_id}: {exc}")
        raise self.retry(exc=exc) from exc
    except Exception as exc:
        logger.error(f"Unexpected error forwarding to SIEM: {exc}")
        return f"Error: {exc}"
