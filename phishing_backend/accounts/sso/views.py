from django.http import HttpResponse
from rest_framework import status
from rest_framework.decorators import (
    api_view,
    authentication_classes,
    permission_classes,
)
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response

from accounts.authentication import PhishGuardDualAuthentication
from accounts.models import Organization, SSOConfiguration
from accounts.permissions import IsOrgAdmin

from .services import (
    authenticate_or_provision_sso_user,
    generate_saml_login_url,
    generate_sp_metadata,
    parse_saml_response,
)


@api_view(["GET"])
@permission_classes([AllowAny])
def sso_metadata_api(request, org_slug):
    """
    Returns SAML 2.0 Service Provider Metadata XML for IdP configuration.
    """
    try:
        org = Organization.objects.get(slug=org_slug)
    except Organization.DoesNotExist:
        return Response({"error": "Organization not found."}, status=status.HTTP_404_NOT_FOUND)

    base_url = request.build_absolute_uri("/").rstrip("/")
    metadata_xml = generate_sp_metadata(org, base_url)
    return HttpResponse(metadata_xml, content_type="application/xml")


@api_view(["POST"])
@permission_classes([AllowAny])
def sso_initiate_api(request):
    """
    Initiates SSO login flow by returning the IdP redirect URL.
    Input: {"email": "analyst@bankcorp.in"} or {"org_slug": "bankcorp"}
    """
    email = request.data.get("email", "").strip().lower()
    org_slug = request.data.get("org_slug", "").strip()

    sso_config = None
    if org_slug:
        sso_config = SSOConfiguration.objects.filter(organization__slug=org_slug, is_enabled=True).first()
    elif email and "@" in email:
        domain = email.split("@")[-1]
        sso_config = SSOConfiguration.objects.filter(enforce_sso_for_domain__iexact=domain, is_enabled=True).first()

    if not sso_config or not sso_config.idp_sso_url:
        return Response(
            {"success": False, "message": "Enterprise SSO is not configured or enabled for this domain/organization."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    base_url = request.build_absolute_uri("/").rstrip("/")
    login_url = generate_saml_login_url(sso_config, base_url)

    return Response(
        {
            "success": True,
            "sso_url": login_url,
            "organization": sso_config.organization.name,
            "idp_entity_id": sso_config.idp_entity_id,
        }
    )


@api_view(["POST"])
@permission_classes([AllowAny])
def sso_acs_api(request, org_slug):
    """
    Assertion Consumer Service (ACS) endpoint.
    Accepts SAMLResponse POST payload from IdP, authenticates/provisions user, and issues JWT tokens.
    """
    try:
        org = Organization.objects.get(slug=org_slug)
        sso_config = org.sso_config
        if not sso_config.is_enabled:
            return Response({"error": "SSO is disabled for this organization."}, status=status.HTTP_403_FORBIDDEN)
    except (Organization.DoesNotExist, SSOConfiguration.DoesNotExist):
        return Response({"error": "Organization or SSO config not found."}, status=status.HTTP_404_NOT_FOUND)

    saml_response = request.data.get("SAMLResponse") or request.POST.get("SAMLResponse")
    if not saml_response:
        return Response({"error": "Missing SAMLResponse parameter."}, status=status.HTTP_400_BAD_REQUEST)

    try:
        user_info = parse_saml_response(saml_response)
        user, tokens = authenticate_or_provision_sso_user(org, user_info)

        return Response(
            {
                "success": True,
                "message": "SSO authentication successful.",
                "user": {
                    "id": user.id,
                    "username": user.username,
                    "email": user.email,
                    "first_name": user.first_name,
                    "last_name": user.last_name,
                },
                "tokens": tokens,
            }
        )
    except Exception as exc:
        return Response({"success": False, "error": str(exc)}, status=status.HTTP_400_BAD_REQUEST)


@api_view(["GET", "PUT"])
@authentication_classes([PhishGuardDualAuthentication])
@permission_classes([IsAuthenticated, IsOrgAdmin])
def sso_config_api(request):
    """
    Admin endpoint to view or update SAML SSO settings for the organization.
    """
    membership = request.user.memberships.first()
    if not membership:
        return Response({"error": "No organization found."}, status=status.HTTP_404_NOT_FOUND)

    org = membership.organization
    config, _ = SSOConfiguration.objects.get_or_create(organization=org)

    if request.method == "GET":
        base_url = request.build_absolute_uri("/").rstrip("/")
        return Response(
            {
                "is_enabled": config.is_enabled,
                "idp_entity_id": config.idp_entity_id,
                "idp_sso_url": config.idp_sso_url,
                "idp_x509_cert": config.idp_x509_cert,
                "enforce_sso_for_domain": config.enforce_sso_for_domain,
                "sp_metadata_url": f"{base_url}/api/auth/sso/metadata/{org.slug}/",
                "sp_acs_url": f"{base_url}/api/auth/sso/acs/{org.slug}/",
            }
        )

    # PUT update
    data = request.data
    config.is_enabled = data.get("is_enabled", config.is_enabled)
    config.idp_entity_id = data.get("idp_entity_id", config.idp_entity_id)
    config.idp_sso_url = data.get("idp_sso_url", config.idp_sso_url)
    config.idp_x509_cert = data.get("idp_x509_cert", config.idp_x509_cert)
    config.enforce_sso_for_domain = data.get("enforce_sso_for_domain", config.enforce_sso_for_domain)
    config.save()

    # Log audit event
    from accounts.audit.services import log_audit_event
    log_audit_event(
        organization=org,
        actor_user=request.user,
        action="sso.config.update",
        target_type="SSOConfiguration",
        target_id=str(config.id),
        ip_address=request.META.get("REMOTE_ADDR"),
        details={"is_enabled": config.is_enabled, "domain": config.enforce_sso_for_domain},
    )

    return Response({"success": True, "message": "SSO configuration updated successfully."})
