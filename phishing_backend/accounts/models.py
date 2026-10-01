import hashlib
import secrets

from django.conf import settings
from django.db import models
from django.utils import timezone


class Plan(models.Model):
    name = models.CharField(max_length=100)
    slug = models.SlugField(max_length=100, unique=True)
    daily_scan_limit = models.IntegerField(default=20, help_text="-1 indicates unlimited scans")
    features = models.JSONField(default=dict, blank=True)
    price_inr = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.name} (Limit: {self.daily_scan_limit}/day)"

    @classmethod
    def get_default_plan(cls):
        plan, _ = cls.objects.get_or_create(
            slug="free",
            defaults={
                "name": "Free",
                "daily_scan_limit": 20,
                "price_inr": 0.00,
                "features": {"api_access": False, "team_seats": 1, "domain_cache": True},
            },
        )
        return plan


class Organization(models.Model):
    name = models.CharField(max_length=255)
    slug = models.SlugField(max_length=255, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name

    def get_active_plan(self):
        try:
            subscription = self.subscription
            if subscription.is_active:
                return subscription.plan
        except Exception:
            pass
        return Plan.get_default_plan()


class Membership(models.Model):
    ROLE_OWNER = "owner"
    ROLE_ADMIN = "admin"
    ROLE_MEMBER = "member"

    ROLE_CHOICES = [
        (ROLE_OWNER, "Owner"),
        (ROLE_ADMIN, "Admin"),
        (ROLE_MEMBER, "Member"),
    ]

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="memberships",
    )
    organization = models.ForeignKey(
        Organization,
        on_delete=models.CASCADE,
        related_name="memberships",
    )
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default=ROLE_MEMBER)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ("user", "organization")

    def __str__(self):
        return f"{self.user.username} ({self.role}) @ {self.organization.name}"


class Subscription(models.Model):
    STATUS_ACTIVE = "active"
    STATUS_PAST_DUE = "past_due"
    STATUS_CANCELLED = "cancelled"
    STATUS_TRIALING = "trialing"

    STATUS_CHOICES = [
        (STATUS_ACTIVE, "Active"),
        (STATUS_PAST_DUE, "Past Due"),
        (STATUS_CANCELLED, "Cancelled"),
        (STATUS_TRIALING, "Trialing"),
    ]

    organization = models.OneToOneField(
        Organization,
        on_delete=models.CASCADE,
        related_name="subscription",
    )
    plan = models.ForeignKey(
        Plan,
        on_delete=models.PROTECT,
        related_name="subscriptions",
    )
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default=STATUS_ACTIVE)
    razorpay_subscription_id = models.CharField(max_length=255, blank=True)
    current_period_end = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    @property
    def is_active(self):
        return self.status in [self.STATUS_ACTIVE, self.STATUS_TRIALING]

    def __str__(self):
        return f"{self.organization.name} - {self.plan.name} ({self.status})"


class APIKey(models.Model):
    organization = models.ForeignKey(
        Organization,
        on_delete=models.CASCADE,
        related_name="api_keys",
    )
    name = models.CharField(max_length=100)
    prefix = models.CharField(max_length=8, db_index=True)
    hashed_key = models.CharField(max_length=128)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    revoked_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"{self.name} ({self.prefix}...) - {self.organization.name}"

    @classmethod
    def generate_key(cls, organization, name):
        secret = secrets.token_urlsafe(32)
        raw_key = f"pg_{secret}"
        prefix = raw_key[:8]
        hashed = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()

        instance = cls.objects.create(
            organization=organization,
            name=name,
            prefix=prefix,
            hashed_key=hashed,
            is_active=True,
        )
        return instance, raw_key

    def verify_key(self, raw_key: str) -> bool:
        if not self.is_active:
            return False
        computed_hash = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()
        return secrets.compare_digest(computed_hash, self.hashed_key)

    def revoke(self):
        self.is_active = False
        self.revoked_at = timezone.now()
        self.save(update_fields=["is_active", "revoked_at"])


class UsageLog(models.Model):
    """
    Privacy-compliant scan logging.
    Stores domain + SHA-256 hash of normalized URL to avoid storing PII/sensitive tokens.
    """
    organization = models.ForeignKey(
        Organization,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="usage_logs",
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="usage_logs",
    )
    domain = models.CharField(max_length=255, db_index=True)
    url_hash = models.CharField(max_length=64, db_index=True, help_text="SHA-256 hash of normalized URL")
    verdict = models.CharField(max_length=30)
    risk_level = models.CharField(max_length=30)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.domain} ({self.verdict}) @ {self.created_at}"
