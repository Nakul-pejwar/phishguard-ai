import hashlib

import pytest

from scanner.intel.feeds import ThreatIntelManager
from scanner.intel.models import ThreatFeedEntry
from scanner.intel.tasks import sync_threat_intel_feeds


@pytest.mark.django_db
def test_threat_feed_manager_and_lookup():
    manager = ThreatIntelManager.get_instance()
    test_url = "http://known-malicious-phishing-feed-url.com/login"
    url_hash = hashlib.sha256(test_url.encode("utf-8")).hexdigest()
    domain = "known-malicious-phishing-feed-url.com"

    # Add entry
    entry = manager.add_feed_entry(domain=domain, url_hash=url_hash, source=ThreatFeedEntry.SOURCE_OPENPHISH)
    assert entry.source == ThreatFeedEntry.SOURCE_OPENPHISH

    # Lookup
    is_threat, source = manager.check_threat_intel(url_hash, domain)
    assert is_threat is True
    assert source is not None


@pytest.mark.django_db
def test_sync_threat_intel_feeds_task():
    synced = sync_threat_intel_feeds()
    assert synced > 0
    assert ThreatFeedEntry.objects.count() >= synced
