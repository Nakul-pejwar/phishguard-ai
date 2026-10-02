import base64
import logging
import xml.etree.ElementTree as ET
from urllib.parse import urlencode

from django.contrib.auth.models import User
from rest_framework_simplejwt.tokens import RefreshToken

from accounts.models import Membership, Organization, SSOConfiguration

logger = logging.getLogger(__name__)


def generate_sp_metadata(organization: Organization, base_url: str) -> str:
    """
    Generates SAML 2.0 Service Provider (SP) Metadata XML for IdP onboarding.
    """
    entity_id = f"{base_url}/api/auth/sso/metadata/{organization.slug}/"
    acs_url = f"{base_url}/api/auth/sso/acs/{organization.slug}/"

    metadata_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                     entityID="{entity_id}">
    <md:SPSSODescriptor AuthnRequestsSigned="false"
                        WantAssertionsSigned="true"
                        protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
        <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                                     Location="{acs_url}"
                                     index="1"
                                     isDefault="true"/>
    </md:SPSSODescriptor>
</md:EntityDescriptor>"""
    return metadata_xml.strip()


def generate_saml_login_url(sso_config: SSOConfiguration, base_url: str) -> str:
    """
    Generates the IdP redirection URL with an AuthN request query.
    """
    acs_url = f"{base_url}/api/auth/sso/acs/{sso_config.organization.slug}/"
    params = {
        "SAMLRequest": base64.b64encode(f"<AuthnRequest ACS='{acs_url}'/>".encode()).decode(),
        "RelayState": sso_config.organization.slug,
    }
    sep = "&" if "?" in sso_config.idp_sso_url else "?"
    return f"{sso_config.idp_sso_url}{sep}{urlencode(params)}"


def _extract_saml_attributes(root: ET.Element) -> tuple[str | None, str, str]:
    """Helper to extract email, first name, and last name from SAML XML."""
    name_id_elem = root.find(".//{urn:oasis:names:tc:SAML:2.0:assertion}NameID")
    if name_id_elem is None:
        name_id_elem = root.find(".//NameID")
    email = name_id_elem.text.strip().lower() if name_id_elem is not None and name_id_elem.text else None

    first_name = ""
    last_name = ""
    attr_elements = root.findall(".//{urn:oasis:names:tc:SAML:2.0:assertion}Attribute") or root.findall(".//Attribute")

    for attr in attr_elements:
        name = attr.get("Name", "").lower()
        val_elem = attr.find(".//{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue")
        if val_elem is None:
            val_elem = attr.find(".//AttributeValue")
        val = val_elem.text.strip() if val_elem is not None and val_elem.text else ""

        if not email and ("email" in name or "mail" in name):
            email = val.lower()
        elif "firstname" in name or "givenname" in name:
            first_name = val
        elif "lastname" in name or "surname" in name:
            last_name = val

    return email, first_name, last_name


def parse_saml_response(saml_response_b64: str) -> dict:
    """
    Decodes and parses SAML Response XML payload, extracting NameID (email) and attributes.
    """
    try:
        try:
            xml_text = base64.b64decode(saml_response_b64).decode("utf-8")
        except Exception:
            xml_text = saml_response_b64

        root = ET.fromstring(xml_text)
        email, first_name, last_name = _extract_saml_attributes(root)

        if not email:
            raise ValueError("No email address or NameID found in SAML assertion.")

        return {
            "email": email,
            "first_name": first_name,
            "last_name": last_name,
        }

    except Exception as exc:
        logger.error(f"SAML Response parsing error: {exc}")
        raise ValueError(f"Invalid SAML response: {exc}") from exc


def authenticate_or_provision_sso_user(organization: Organization, user_info: dict) -> tuple[User, dict]:
    """
    Locates or auto-provisions the user and membership, and returns JWT tokens.
    """
    email = user_info["email"].lower().strip()

    user, _ = User.objects.get_or_create(
        email=email,
        defaults={
            "username": email,
            "first_name": user_info.get("first_name", ""),
            "last_name": user_info.get("last_name", ""),
        },
    )

    Membership.objects.get_or_create(
        organization=organization,
        user=user,
        defaults={"role": Membership.ROLE_MEMBER},
    )

    refresh = RefreshToken.for_user(user)
    tokens = {
        "refresh": str(refresh),
        "access": str(refresh.access_token),
    }

    return user, tokens

