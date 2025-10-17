"""
End-to-End tests for the login router.
"""

import jwt
import pytest
import requests
from fastapi.testclient import TestClient
from httpx import Response

from ldap_jwt_auth.core.config import config
from ldap_jwt_auth.core.constants import PUBLIC_KEY


class OIDCLoginDSL:
    """Base class for OIDC login tests."""

    test_client: TestClient
    _keycloak_provider_config = config.oidc_providers["keycloak"]

    _post_response_oidc_login: Response
    _keycloak_id_token: str

    @pytest.fixture(autouse=True)
    def setup_oidc_login_dsl(self, test_client, get_id_token_from_keycloak):
        """Setup fixtures."""
        self.test_client = test_client
        self._keycloak_id_token = get_id_token_from_keycloak

    @pytest.fixture(name="get_keycloak_token_endpoint_url", scope="class")
    def fixture_get_keycloak_token_endpoint_url(self) -> str:
        """
        Fixture for getting the keycloak token endpoint URL from the well known configuration endpoint.
        """
        response = requests.get(self._keycloak_provider_config.configuration_url, timeout=10)
        return response.json()["token_endpoint"]

    @pytest.fixture(name="get_id_token_from_keycloak", scope="class")
    def fixture_get_id_token_from_keycloak(self, get_keycloak_token_endpoint_url) -> str:
        """
        Fixture for getting an ID token from keycloak.
        """
        response = requests.post(
            get_keycloak_token_endpoint_url,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data={
                "grant_type": "password",
                "client_id": config.oidc_providers["keycloak"].client_id,
                "scope": config.oidc_providers["keycloak"].scope,
                "username": "test@example.com",
                "password": "password",
            },
            timeout=10,
        )
        return response.json()["id_token"]

    def post_oidc_id_token(self, authorisation_header_data: str, provider_id: str = "keycloak") -> None:
        """
        Post an OIDC ID token with the given authorization header data.

        :param authorisation_header_data: The data for the Authorization header to be posted in the request.
        :param provider_id: The OIDC provider ID. Defaults to `keycloak`.
        """
        self._post_response_oidc_login = self.test_client.post(
            f"/oidc_login/{provider_id}", headers={"Authorization": authorisation_header_data}
        )

    def check_post_oidc_id_token_success(self) -> None:
        """
        Check that a prior call to `post_oidc_id_token` gave a successful response with the expected data returned.
        """
        assert self._post_response_oidc_login.status_code == 200

        access_token_payload = jwt.decode(
            self._post_response_oidc_login.json(), PUBLIC_KEY, algorithms=[config.authentication.jwt_algorithm]
        )

        assert access_token_payload["username"] == "test@example.com"
        assert access_token_payload["userIsAdmin"] is False

    def check_post_oidc_id_token_failed_with_detail(self, status_code: int, detail: str) -> None:
        """
        Checks that prior call to `post_oidc_id_token` gave a failed response with the expected code and detail.

        :param status_code: Expected status code to be returned.
        :param detail: Expected detail to be returned.
        """
        assert self._post_response_oidc_login.status_code == status_code
        assert self._post_response_oidc_login.json()["detail"] == detail


class TestOIDCLogin(OIDCLoginDSL):
    """Tests for logging in via OIDC."""

    def test_login(self):
        """Test logging in with an OIDC ID token."""
        self.post_oidc_id_token(f"Bearer {self._keycloak_id_token}")
        self.check_post_oidc_id_token_success()

    def test_login_with_invalid_id_token(self):
        """Test logging in with an invalid OIDC ID token."""
        invalid_id_token = self._keycloak_id_token + "1"
        self.post_oidc_id_token(f"Bearer {invalid_id_token}")
        self.check_post_oidc_id_token_failed_with_detail(401, "Invalid OIDC ID token provided")

    def test_login_with_empty_authorisation_header(self):
        """Test logging in with a missing OIDC ID token."""
        self.post_oidc_id_token("")
        self.check_post_oidc_id_token_failed_with_detail(403, "Not authenticated")

    def test_login_with_missing_bearer_token(self):
        """Test logging in with a missing OIDC ID token."""
        self.post_oidc_id_token("Bearer ")
        self.check_post_oidc_id_token_failed_with_detail(403, "Not authenticated")

    def test_login_with_unknown_oidc_provider(self):
        """Test logging in when an unknown OIDC provider is used."""
        self.post_oidc_id_token(f"Bearer {self._keycloak_id_token}", provider_id="unknown")
        self.check_post_oidc_id_token_failed_with_detail(404, "OIDC provider not found")


class OIDCProvidersListDSL(OIDCLoginDSL):
    """Base class for OIDC providers list tests."""

    _get_response_oidc_providers: Response

    def get_oidc_providers(self):
        """Get a list of OIDC providers."""
        self._get_response_oidc_providers = self.test_client.get("/oidc_providers")

    def check_get_oidc_providers_success(self, expected_oidc_providers_get_data: dict[str, dict]) -> None:
        """
        Checks that a prior call to `get_oidc_providers` gave a successful response with the expected data returned.

        :param expected_oidc_providers_get_data: Dictionary of dictionaries containing the expected OIDC providers data.
        """
        assert self._get_response_oidc_providers.status_code == 200
        assert self._get_response_oidc_providers.json() == expected_oidc_providers_get_data


class TestOIDCProvidersList(OIDCProvidersListDSL):
    """Tests for getting a list of OIDC providers."""

    def test_list(self):
        """Test getting a list of all OIDC providers."""
        self.get_oidc_providers()
        self.check_get_oidc_providers_success(
            {
                "keycloak": {
                    "display_name": self._keycloak_provider_config.display_name,
                    "configuration_url": self._keycloak_provider_config.configuration_url,
                    "client_id": self._keycloak_provider_config.client_id,
                    "pkce": True,
                    "scope": self._keycloak_provider_config.scope,
                }
            }
        )
