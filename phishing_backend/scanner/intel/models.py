from django.db import models


class ThreatFeedEntry(models.Model):
    SOURCE_OPENPHISH = "openphish"
    SOURCE_URLHAUS = "urlhaus"
    SOURCE_PHISHTANK = "phishtank"
    SOURCE_MANUAL = "manual"

    SOURCE_CHOICES = [
        (SOURCE_OPENPHISH, "OpenPhish"),
        (SOURCE_URLHAUS, "URLhaus"),
        (SOURCE_PHISHTANK, "PhishTank"),
        (SOURCE_MANUAL, "Manual / Security Analyst"),
    ]

    source = models.CharField(max_length=50, choices=SOURCE_CHOICES, default=SOURCE_OPENPHISH)
    domain = models.CharField(max_length=255, db_index=True)
    url_hash = models.CharField(max_length=64, db_index=True, unique=True, help_text="SHA-256 hash of malicious URL")
    is_active = models.BooleanField(default=True)
    added_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ["-added_at"]
        indexes = [
            models.Index(fields=["domain", "is_active"]),
            models.Index(fields=["url_hash", "is_active"]),
        ]

    def __str__(self):
        return f"[{self.source}] {self.domain} ({self.url_hash[:8]}...)"
