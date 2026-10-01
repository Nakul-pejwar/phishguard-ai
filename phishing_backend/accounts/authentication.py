import hashlib

from rest_framework import authentication, exceptions
from rest_framework_simplejwt.authentication import JWTAuthentication

from .models import APIKey, Membership


class APIKeyUser:
    """Represents an authenticated API key caller."""
    is_authenticated = True
    is_anonymous = False

    def __init__(self, organization, api_key, owner_user=None):
        self.organization = organization
        self.api_key = api_key
        self.owner_user = owner_user
        self.username = f"api_key_{api_key.prefix}"
        self.id = getattr(owner_user, "id", None)
        self.email = getattr(owner_user, "email", "")

    def __str__(self):
        return f"APIKey({self.api_key.name} @ {self.organization.name})"


class PhishGuardDualAuthentication(authentication.BaseAuthentication):
    """
    Dual authentication scheme supporting:
    1. JWT Bearer Tokens (`Authorization: Bearer <token>`)
    2. API Keys (`Authorization: Api-Key <raw_key>` or `X-API-Key: <raw_key>`)
    """

    jwt_auth = JWTAuthentication()

    def authenticate(self, request):
        # 1. Check for API key in headers
        api_key_raw = self.extract_api_key(request)
        if api_key_raw:
            return self.authenticate_api_key(request, api_key_raw)

        # 2. Check for JWT Bearer token
        auth_header = authentication.get_authorization_header(request).split()
        if auth_header and auth_header[0].lower() == b"bearer":
            jwt_result = self.jwt_auth.authenticate(request)
            if jwt_result is not None:
                user, token = jwt_result
                # Attach user's primary organization to request
                membership = Membership.objects.filter(user=user).select_related("organization").first()
                request.organization = membership.organization if membership else None
                return (user, token)

        return None

    def extract_api_key(self, request) -> str | None:
        # Check X-API-Key
        x_api_key = request.META.get("HTTP_X_API_KEY")
        if x_api_key:
            return x_api_key.strip()

        # Check Authorization: Api-Key <key>
        auth_header = authentication.get_authorization_header(request).split()
        if auth_header and auth_header[0].lower() in (b"api-key", b"apikey"):
            if len(auth_header) == 2:
                return auth_header[1].decode("utf-8").strip()

        return None

    def authenticate_api_key(self, request, raw_key: str):
        if not raw_key.startswith("pg_") or len(raw_key) < 10:
            raise exceptions.AuthenticationFailed("Invalid API key format.")

        prefix = raw_key[:8]
        hashed = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()

        try:
            api_key = APIKey.objects.select_related("organization").get(
                prefix=prefix,
                hashed_key=hashed,
                is_active=True,
            )
        except APIKey.DoesNotExist:
            raise exceptions.AuthenticationFailed("Invalid or revoked API key.") from None

        # Find owner of the organization for user reference
        owner_membership = Membership.objects.filter(
            organization=api_key.organization,
            role=Membership.ROLE_OWNER,
        ).select_related("user").first()

        owner_user = owner_membership.user if owner_membership else None
        api_user = APIKeyUser(organization=api_key.organization, api_key=api_key, owner_user=owner_user)

        request.organization = api_key.organization
        request.api_key = api_key
        return (api_user, api_key)
