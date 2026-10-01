import logging

from django.core.cache import cache

from .models import ThreatFeedEntry

logger = logging.getLogger(__name__)


class ThreatIntelManager:
    _instance = None
    _in_memory_hashes = set()
    _in_memory_domains = set()

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def add_feed_entry(self, domain: str, url_hash: str, source: str = ThreatFeedEntry.SOURCE_OPENPHISH):
        entry, _ = ThreatFeedEntry.objects.get_or_create(
            url_hash=url_hash,
            defaults={"domain": domain, "source": source, "is_active": True},
        )
        self._in_memory_hashes.add(url_hash)
        self._in_memory_domains.add(domain)
        cache.set(f"ti_hash:{url_hash}", source, timeout=86400)
        return entry

    def check_threat_intel(self, url_hash: str, domain: str) -> tuple[bool, str | None]:
        """
        Fast multi-tier lookup: In-Memory -> Redis Cache -> Database
        """
        # 1. In-memory check
        if url_hash in self._in_memory_hashes:
            return True, "OpenPhish / Global Threat Intel"

        # 2. Redis cache check
        cached_source = cache.get(f"ti_hash:{url_hash}")
        if cached_source:
            self._in_memory_hashes.add(url_hash)
            return True, f"Threat feed ({cached_source})"

        # 3. Database check
        try:
            entry = ThreatFeedEntry.objects.filter(url_hash=url_hash, is_active=True).first()
            if entry:
                self._in_memory_hashes.add(url_hash)
                cache.set(f"ti_hash:{url_hash}", entry.source, timeout=86400)
                return True, f"Threat feed ({entry.get_source_display()})"
        except Exception:
            pass

        return False, None
