# pylint: disable=no-member
"""
Unit tests for the `authentication` module.
"""
import time
from test.unit.mock_data import JWK_PUBLIC, JWK_PRIVATE_KEY
from unittest.mock import Mock, patch

import jwt
import ldap
import pytest
import requests
from cryptography.hazmat.primitives import serialization
from ldap.ldapobject import LDAPObject

from ldap_jwt_auth.auth.authentication import LDAPAuthentication, OIDCAuthentication
from ldap_jwt_auth.auth.authorisation import Authorisation
from ldap_jwt_auth.core.config import config
from ldap_jwt_auth.core.exceptions import (
    InvalidCredentialsError,
    LDAPServerError,
    UserNotActiveError,
    InvalidJWTError,
    OIDCProviderNotFoundError,
)
from ldap_jwt_auth.core.schemas import UserCredentialsPostRequestSchema


class TestLDAPAuthentication:
    """Tests for the `LDAPAuthentication` class"""

    @patch("ldap_jwt_auth.auth.authentication.ldap.initialize")
    def test_authenticate(self, ldap_initialize_mock):
        """
        Test LDAP authentication with valid credentials.
        """
        ldap_obj_mock = Mock(LDAPObject)
        ldap_obj_mock.simple_bind_s.return_value = (97, [], 2, [])
        ldap_initialize_mock.return_value = ldap_obj_mock

        authentication = LDAPAuthentication()
        user_credentials = UserCredentialsPostRequestSchema(username="username", password="password")
        authentication.authenticate(user_credentials)

        ldap_initialize_mock.assert_called_once_with(config.ldap_server.url.get_secret_value())
        ldap_obj_mock.start_tls_s.assert_called_once()
        ldap_obj_mock.simple_bind_s.assert_called_once_with(
            f"{user_credentials.username.get_secret_value()}@{config.ldap_server.realm.get_secret_value()}",
            user_credentials.password.get_secret_value(),
        )
        ldap_obj_mock.unbind.assert_called_once()

    def test_authenticate_with_empty_credentials(self):
        """
        Test LDAP authentication with empty credentials.
        """
        authentication = LDAPAuthentication()
        user_credentials = UserCredentialsPostRequestSchema(username="", password="")

        with pytest.raises(InvalidCredentialsError) as exc:
            authentication.authenticate(user_credentials)
        assert str(exc.value) == "Empty username or password"

    @patch("ldap_jwt_auth.auth.authentication.ldap.initialize")
    def test_authenticate_with_invalid_credentials(self, ldap_initialize_mock):
        """
        Test LDAP authentication with invalid credentials.
        """
        ldap_obj_mock = Mock(LDAPObject)
        ldap_obj_mock.simple_bind_s.side_effect = ldap.INVALID_CREDENTIALS
        ldap_initialize_mock.return_value = ldap_obj_mock

        authentication = LDAPAuthentication()
        user_credentials = UserCredentialsPostRequestSchema(username="username", password="password")

        with pytest.raises(InvalidCredentialsError) as exc:
            authentication.authenticate(user_credentials)
        assert str(exc.value) == "Invalid username or password"
        ldap_initialize_mock.assert_called_once_with(config.ldap_server.url.get_secret_value())
        ldap_obj_mock.start_tls_s.assert_called_once()
        ldap_obj_mock.simple_bind_s.assert_called_once_with(
            f"{user_credentials.username.get_secret_value()}@{config.ldap_server.realm.get_secret_value()}",
            user_credentials.password.get_secret_value(),
        )
        ldap_obj_mock.unbind.assert_called_once()

    def test_authenticate_with_not_active_username(self):
        """
        Test LDAP authentication with username that is not active.
        """
        authentication = LDAPAuthentication()
        username = "username_not_active"
        user_credentials = UserCredentialsPostRequestSchema(username=username, password="password")

        with pytest.raises(UserNotActiveError) as exc:
            authentication.authenticate(user_credentials)
        assert str(exc.value) == f"The provided username '{username}' is not part of the active usernames"

    @patch("ldap_jwt_auth.auth.authentication.ldap.initialize")
    def test_authenticate_ldap_server_error(self, ldap_initialize_mock):
        """
        Test LDAP authentication when server error occurs.
        """
        ldap_obj_mock = Mock(LDAPObject)
        ldap_obj_mock.start_tls_s.side_effect = ldap.LDAPError
        ldap_initialize_mock.return_value = ldap_obj_mock

        authentication = LDAPAuthentication()
        user_credentials = UserCredentialsPostRequestSchema(username="username", password="password")

        with pytest.raises(LDAPServerError) as exc:
            authentication.authenticate(user_credentials)
        assert str(exc.value) == "Problem with LDAP server"
        ldap_initialize_mock.assert_called_once_with(config.ldap_server.url.get_secret_value())
        ldap_obj_mock.start_tls_s.assert_called_once()
        ldap_obj_mock.unbind.assert_not_called()


class TestOIDCAuthentication:
    """Tests for the `OIDCAuthentication` class"""

    oidc_authentication: OIDCAuthentication

    @pytest.fixture(autouse=True)
    def setup(self):
        """Setup fixtures."""
        config.oidc_providers["keycloak"].configuration_url = (
            "https://mock-oidc-provider/.well-known/openid-configuration"
        )
        self.oidc_authentication = OIDCAuthentication()
        self.oidc_authentication._authorisation = Mock(Authorisation)  # pylint: disable=protected-access

    def mock_requests_get(self, url, **kwargs):  # pylint: disable=unused-argument
        """Mock calls to `requests.get`."""

        class MockRequestsResponse:
            # pylint: disable=missing-class-docstring,missing-function-docstring

            def __init__(self, json):
                self._json = json

            def raise_for_status(self):
                pass

            def json(self):
                return self._json

        if url == "https://mock-oidc-provider/.well-known/openid-configuration":
            return MockRequestsResponse(
                {
                    "issuer": "https://mock-oidc-provider/issuer",
                    "jwks_uri": "https://mock-oidc-provider/issuer/keys",
                    "token_endpoint": "https://mock-oidc-provider/issuer/token",
                }
            )

        if url == "https://mock-oidc-provider/issuer/keys":
            return MockRequestsResponse({"keys": [JWK_PUBLIC]})

        raise requests.ConnectionError

    def create_oidc_id_token_payload(self):
        """Generate a payload for an OIDC ID token."""
        return {
            "email": "test@example.com",
            "iss": "https://mock-oidc-provider/issuer",
            "aud": "test-client-id",
            "iat": int(time.time()),
            "exp": int(time.time()) + 600,
        }

    def create_oidc_id_token(self, payload=None, headers=None):
        """Generate an OIDC ID token."""
        if headers is None:
            headers = {"kid": "mock-kid"}

        if payload is None:
            payload = self.create_oidc_id_token_payload()

        private_key = serialization.load_pem_private_key(JWK_PRIVATE_KEY.encode(), None)
        return jwt.encode(payload, private_key, algorithm="RS256", headers=headers)

    @patch("requests.get")
    def test_authenticate(self, mock_get):
        """Test authenticating a user with an OIDC ID token."""
        mock_get.side_effect = self.mock_requests_get
        self.oidc_authentication._authorisation.is_active_user.return_value = True  # pylint: disable=protected-access

        username = self.oidc_authentication.authenticate("keycloak", self.create_oidc_id_token())
        assert username == "test@example.com"

    @patch("requests.get")
    def test_authenticate_with_expired_id_token(self, mock_get):
        """Test authenticating a user when the OIDC ID token is expired."""
        mock_get.side_effect = self.mock_requests_get

        id_token_payload = self.create_oidc_id_token_payload()
        id_token_payload["exp"] = int(time.time()) - 10

        with pytest.raises(InvalidJWTError):
            self.oidc_authentication.authenticate("keycloak", self.create_oidc_id_token(id_token_payload))

        del id_token_payload["exp"]
        with pytest.raises(InvalidJWTError):
            self.oidc_authentication.authenticate("keycloak", self.create_oidc_id_token(id_token_payload))

    @patch("requests.get")
    def test_authenticate_with_invalid_id_token_audience(self, mock_get):
        """Test authenticating a user when the audience is missing in the OIDC ID token."""
        mock_get.side_effect = self.mock_requests_get

        id_token_payload = self.create_oidc_id_token_payload()
        id_token_payload["aud"] = "invalid"

        with pytest.raises(InvalidJWTError):
            self.oidc_authentication.authenticate("keycloak", self.create_oidc_id_token(id_token_payload))

        del id_token_payload["aud"]

        with pytest.raises(InvalidJWTError):
            self.oidc_authentication.authenticate("keycloak", self.create_oidc_id_token(id_token_payload))

    @patch("requests.get")
    def test_authenticate_with_invalid_id_token_issuer(self, mock_get):
        """Test authenticating a user when the issuer is missing in the OIDC ID token."""
        mock_get.side_effect = self.mock_requests_get

        id_token_payload = self.create_oidc_id_token_payload()
        id_token_payload["iss"] = "invalid"

        with pytest.raises(InvalidJWTError):
            self.oidc_authentication.authenticate("keycloak", self.create_oidc_id_token(id_token_payload))

        del id_token_payload["iss"]

        with pytest.raises(InvalidJWTError):
            self.oidc_authentication.authenticate("keycloak", self.create_oidc_id_token(id_token_payload))

    @patch("requests.get")
    def test_authenticate_with_missing_id_token_email(self, mock_get):
        """Test authenticating a user when the email is missing in the OIDC ID token."""
        mock_get.side_effect = self.mock_requests_get

        id_token_payload = self.create_oidc_id_token_payload()
        del id_token_payload["email"]

        with pytest.raises(InvalidJWTError):
            self.oidc_authentication.authenticate("keycloak", self.create_oidc_id_token(id_token_payload))

    @patch("requests.get")
    def test_authenticate_with_missing_kid_header(self, mock_get):
        """Test authenticating a user when the kid header is missing."""
        mock_get.side_effect = self.mock_requests_get

        with pytest.raises(InvalidJWTError):
            self.oidc_authentication.authenticate("keycloak", self.create_oidc_id_token(headers={}))

    @patch("requests.get")
    def test_authenticate_with_unknown_key(self, mock_get):
        """Test authenticating a user when the kid header is unknown."""
        mock_get.side_effect = self.mock_requests_get

        with pytest.raises(InvalidJWTError):
            self.oidc_authentication.authenticate("keycloak", self.create_oidc_id_token(headers={"kid": "unknown"}))

    def test_authenticate_with_unknown_provider_id(self):
        """Test authenticating a user with an unknown OIDC provider."""
        with pytest.raises(OIDCProviderNotFoundError):
            self.oidc_authentication.authenticate("unknown", self.create_oidc_id_token())
