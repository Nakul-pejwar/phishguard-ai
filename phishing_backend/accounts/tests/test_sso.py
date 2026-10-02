import base64

import pytest
from django.contrib.auth.models import User
from rest_framework.test import APIClient

from accounts.models import Membership, Organization, SSOConfiguration
from accounts.sso.services import (
    authenticate_or_provision_sso_user,
    generate_saml_login_url,
    generate_sp_metadata,
    parse_saml_response,
)


@pytest.mark.django_db
class TestEnterpriseSSO:
    def setup_method(self):
        self.client = APIClient()
        self.user = User.objects.create_user(
            username="admin@bankcorp.in",
            email="admin@bankcorp.in",
            password="adminpassword123",
        )
        self.org = Organization.objects.create(name="Bank Corp India", slug="bankcorp")
        self.membership = Membership.objects.create(
            organization=self.org,
            user=self.user,
            role=Membership.ROLE_ADMIN,
        )
        self.sso_config = SSOConfiguration.objects.create(
            organization=self.org,
            idp_entity_id="http://idp.okta.com/exk12345",
            idp_sso_url="https://idp.okta.com/app/sso",
            idp_x509_cert="MIIC...CERT",
            enforce_sso_for_domain="bankcorp.in",
            is_enabled=True,
        )
        self.client.force_authenticate(user=self.user)

    def test_sp_metadata_generation(self):
        metadata = generate_sp_metadata(self.org, "https://api.phishguard.ai")
        assert "EntityDescriptor" in metadata
        assert f"/api/auth/sso/acs/{self.org.slug}/" in metadata
        assert f"/api/auth/sso/metadata/{self.org.slug}/" in metadata

    def test_sp_metadata_api(self):
        resp = self.client.get(f"/api/auth/sso/metadata/{self.org.slug}/")
        assert resp.status_code == 200
        assert resp["Content-Type"] == "application/xml"
        assert "EntityDescriptor" in resp.content.decode("utf-8")

    def test_saml_login_url_generation(self):
        url = generate_saml_login_url(self.sso_config, "https://api.phishguard.ai")
        assert url.startswith("https://idp.okta.com/app/sso?")
        assert "SAMLRequest=" in url
        assert "RelayState=bankcorp" in url

    def test_sso_initiate_api(self):
        # By email
        resp = self.client.post(
            "/api/auth/sso/initiate/",
            {"email": "employee@bankcorp.in"},
            format="json",
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        assert "sso_url" in data
        assert data["organization"] == "Bank Corp India"

        # By org_slug
        resp_slug = self.client.post(
            "/api/auth/sso/initiate/",
            {"org_slug": "bankcorp"},
            format="json",
        )
        assert resp_slug.status_code == 200

    def test_parse_saml_response_and_provision(self):
        sample_xml = """<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
            <saml:Assertion>
                <saml:Subject>
                    <saml:NameID>analyst@bankcorp.in</saml:NameID>
                </saml:Subject>
                <saml:AttributeStatement>
                    <saml:Attribute Name="firstName">
                        <saml:AttributeValue>Rohan</saml:AttributeValue>
                    </saml:Attribute>
                    <saml:Attribute Name="lastName">
                        <saml:AttributeValue>Sharma</saml:AttributeValue>
                    </saml:Attribute>
                </saml:AttributeStatement>
            </saml:Assertion>
        </samlp:Response>"""

        parsed = parse_saml_response(sample_xml)
        assert parsed["email"] == "analyst@bankcorp.in"
        assert parsed["first_name"] == "Rohan"
        assert parsed["last_name"] == "Sharma"

        user, tokens = authenticate_or_provision_sso_user(self.org, parsed)
        assert user.email == "analyst@bankcorp.in"
        assert user.first_name == "Rohan"
        assert "access" in tokens
        assert "refresh" in tokens

        # Verify membership auto-provisioned
        assert Membership.objects.filter(organization=self.org, user=user).exists()

    def test_sso_acs_endpoint(self):
        sample_xml = """<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
            <saml:Assertion>
                <saml:Subject>
                    <saml:NameID>officer@bankcorp.in</saml:NameID>
                </saml:Subject>
            </saml:Assertion>
        </samlp:Response>"""
        b64_payload = base64.b64encode(sample_xml.encode("utf-8")).decode()

        resp = self.client.post(
            f"/api/auth/sso/acs/{self.org.slug}/",
            {"SAMLResponse": b64_payload},
            format="json",
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        assert data["user"]["email"] == "officer@bankcorp.in"
        assert "tokens" in data

    def test_sso_config_api_admin(self):
        resp = self.client.get("/api/auth/sso/config/")
        assert resp.status_code == 200
        assert resp.json()["idp_entity_id"] == "http://idp.okta.com/exk12345"

        update_resp = self.client.put(
            "/api/auth/sso/config/",
            {"enforce_sso_for_domain": "corp.bank.in", "is_enabled": False},
            format="json",
        )
        assert update_resp.status_code == 200
        self.sso_config.refresh_from_db()
        assert self.sso_config.enforce_sso_for_domain == "corp.bank.in"
        assert self.sso_config.is_enabled is False
