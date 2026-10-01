from django.utils import timezone
from rest_framework import permissions, status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken

from .authentication import PhishGuardDualAuthentication
from .models import APIKey, Membership, UsageLog
from .serializers import (
    APIKeyCreateSerializer,
    APIKeySerializer,
    LoginSerializer,
    OrganizationSerializer,
    RegisterSerializer,
    UserSerializer,
)


class RegisterView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()

        # Generate JWT
        refresh = RefreshToken.for_user(user)
        membership = Membership.objects.filter(user=user).select_related("organization__subscription__plan").first()
        org = membership.organization if membership else None

        return Response(
            {
                "success": True,
                "message": "User registered successfully.",
                "tokens": {
                    "access": str(refresh.access_token),
                    "refresh": str(refresh),
                },
                "user": UserSerializer(user).data,
                "organization": OrganizationSerializer(org).data if org else None,
            },
            status=status.HTTP_201_CREATED,
        )


class LoginView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data["user"]

        refresh = RefreshToken.for_user(user)
        membership = Membership.objects.filter(user=user).select_related("organization__subscription__plan").first()
        org = membership.organization if membership else None

        return Response(
            {
                "success": True,
                "tokens": {
                    "access": str(refresh.access_token),
                    "refresh": str(refresh),
                },
                "user": UserSerializer(user).data,
                "organization": OrganizationSerializer(org).data if org else None,
            },
            status=status.HTTP_200_OK,
        )


class MeView(APIView):
    authentication_classes = [PhishGuardDualAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        user = request.user
        org = getattr(request, "organization", None)

        if not org and hasattr(user, "id"):
            membership = Membership.objects.filter(user=user).select_related("organization__subscription__plan").first()
            org = membership.organization if membership else None

        today_start = timezone.now().replace(hour=0, minute=0, second=0, microsecond=0)
        daily_limit = 20
        plan_name = "free"

        if org:
            plan = org.get_active_plan()
            daily_limit = plan.daily_scan_limit
            plan_name = plan.slug
            today_scans = UsageLog.objects.filter(organization=org, created_at__gte=today_start).count()
        else:
            today_scans = 0

        remaining = max(0, daily_limit - today_scans) if daily_limit != -1 else "unlimited"

        return Response(
            {
                "success": True,
                "user": UserSerializer(user).data if hasattr(user, "username") else {"username": str(user)},
                "organization": OrganizationSerializer(org).data if org else None,
                "quota": {
                    "plan": plan_name,
                    "daily_limit": daily_limit,
                    "used_today": today_scans,
                    "remaining_today": remaining,
                },
            }
        )


class APIKeyListCreateView(APIView):
    authentication_classes = [PhishGuardDualAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        org = getattr(request, "organization", None)
        if not org:
            return Response({"success": False, "message": "No organization associated with this account."}, status=status.HTTP_400_BAD_REQUEST)

        keys = APIKey.objects.filter(organization=org).order_by("-created_at")
        return Response({"success": True, "api_keys": APIKeySerializer(keys, many=True).data})

    def post(self, request):
        org = getattr(request, "organization", None)
        if not org:
            return Response({"success": False, "message": "No organization associated with this account."}, status=status.HTTP_400_BAD_REQUEST)

        serializer = APIKeyCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        name = serializer.validated_data["name"]

        api_key_obj, raw_key = APIKey.generate_key(organization=org, name=name)

        return Response(
            {
                "success": True,
                "message": "API key generated successfully. Store this secret safely; it will not be shown again.",
                "raw_key": raw_key,
                "api_key": APIKeySerializer(api_key_obj).data,
            },
            status=status.HTTP_201_CREATED,
        )


class APIKeyRevokeView(APIView):
    authentication_classes = [PhishGuardDualAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, pk):
        org = getattr(request, "organization", None)
        if not org:
            return Response({"success": False, "message": "No organization associated."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            api_key = APIKey.objects.get(pk=pk, organization=org)
            api_key.revoke()
            return Response({"success": True, "message": f"API key '{api_key.name}' revoked successfully."})
        except APIKey.DoesNotExist:
            return Response({"success": False, "message": "API key not found."}, status=status.HTTP_404_NOT_FOUND)
