from django.db import models


class URLScanResult(models.Model):
    input_url = models.URLField(max_length=2048)
    clean_url = models.URLField(max_length=2048)
    domain = models.CharField(max_length=255)

    verdict = models.CharField(max_length=30)
    risk_level = models.CharField(max_length=30)

    raw_phishing_probability = models.FloatField(default=0)
    phishing_probability = models.FloatField(default=0)
    legitimate_probability = models.FloatField(default=0)

    reasons = models.JSONField(default=list, blank=True)

    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.verdict} - {self.domain}"