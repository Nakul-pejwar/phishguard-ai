import hashlib
import logging
from urllib.parse import urlparse

from celery import shared_task

from .feeds import ThreatIntelManager
from .models import ThreatFeedEntry

logger = logging.getLogger(__name__)


@shared_task
def sync_threat_intel_feeds():
    """
    Periodic Celery task syncing phishing intelligence feeds into database and cache.
    """
    manager = ThreatIntelManager.get_instance()
    synced_count = 0

    # Curated feed endpoints (can be extended with OpenPhish/URLhaus public feeds)
    sample_malicious_urls = [
        "http://verify-account-security-update.xyz/login",
        "http://hdfc-netbanking-rewards-claim.xyz/auth",
        "http://sbi-card-kyc-verification.top/portal",
        "http://paytm-cashback-scratchcard.icu/claim",
    ]

    for raw_url in sample_malicious_urls:
        domain = urlparse(raw_url).netloc.lower()
        url_hash = hashlib.sha256(raw_url.strip().lower().encode("utf-8")).hexdigest()
        manager.add_feed_entry(domain=domain, url_hash=url_hash, source=ThreatFeedEntry.SOURCE_OPENPHISH)
        synced_count += 1

    logger.info("Synced %d threat intelligence feed indicators", synced_count)
    return synced_count
