from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from django.utils.text import slugify
from rest_framework import serializers

from .models import APIKey, Membership, Organization, Plan, Subscription, UsageLog


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["id", "username", "email", "first_name", "last_name"]


class PlanSerializer(serializers.ModelSerializer):
    class Meta:
        model = Plan
        fields = ["id", "name", "slug", "daily_scan_limit", "features", "price_inr"]


class SubscriptionSerializer(serializers.ModelSerializer):
    plan = PlanSerializer(read_only=True)

    class Meta:
        model = Subscription
        fields = ["id", "status", "plan", "current_period_end", "is_active"]


class OrganizationSerializer(serializers.ModelSerializer):
    subscription = SubscriptionSerializer(read_only=True)

    class Meta:
        model = Organization
        fields = ["id", "name", "slug", "created_at", "subscription"]


class RegisterSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True, min_length=8)
    org_name = serializers.CharField(required=False, allow_blank=True)

    def validate_email(self, value):
        normalized_email = value.strip().lower()
        if User.objects.filter(username__iexact=normalized_email).exists() or User.objects.filter(email__iexact=normalized_email).exists():
            raise serializers.ValidationError("A user with this email address already exists.")
        return normalized_email

    def create(self, validated_data):
        email = validated_data["email"]
        password = validated_data["password"]
        org_name = validated_data.get("org_name", "").strip() or f"{email.split('@')[0]}'s Org"

        # Create user
        user = User.objects.create_user(
            username=email,
            email=email,
            password=password,
        )

        # Create default organization & slug
        base_slug = slugify(org_name) or f"org-{user.id}"
        slug = base_slug
        counter = 1
        while Organization.objects.filter(slug=slug).exists():
            slug = f"{base_slug}-{counter}"
            counter += 1

        org = Organization.objects.create(name=org_name, slug=slug)

        # Owner membership
        Membership.objects.create(
            user=user,
            organization=org,
            role=Membership.ROLE_OWNER,
        )

        # Default free subscription
        free_plan = Plan.get_default_plan()
        Subscription.objects.create(
            organization=org,
            plan=free_plan,
            status=Subscription.STATUS_ACTIVE,
        )

        return user


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def validate(self, attrs):
        email = attrs.get("email", "").strip().lower()
        password = attrs.get("password")

        user = authenticate(username=email, password=password)
        if not user:
            raise serializers.ValidationError("Invalid email or password.")

        if not user.is_active:
            raise serializers.ValidationError("This account is inactive.")

        attrs["user"] = user
        return attrs


class APIKeySerializer(serializers.ModelSerializer):
    class Meta:
        model = APIKey
        fields = ["id", "name", "prefix", "is_active", "created_at", "revoked_at"]
        read_only_fields = ["id", "prefix", "is_active", "created_at", "revoked_at"]


class APIKeyCreateSerializer(serializers.Serializer):
    name = serializers.CharField(max_length=100)


class UsageLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = UsageLog
        fields = [
            "id",
            "domain",
            "url_hash",
            "verdict",
            "risk_level",
            "created_at",
        ]
