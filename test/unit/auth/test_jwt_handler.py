"""
Unit tests for the `JWTHandler` class.
"""

from datetime import datetime, timezone
from test.unit.mock_data import (
    EXPIRED_ACCESS_TOKEN,
    EXPIRED_REFRESH_TOKEN,
    EXPECTED_ACCESS_TOKEN,
    EXPECTED_REFRESH_TOKEN,
    VALID_ACCESS_TOKEN,
    VALID_REFRESH_TOKEN,
)
from unittest.mock import patch

import pytest

from ldap_jwt_auth.auth.jwt_handler import JWTHandler
from ldap_jwt_auth.core.exceptions import InvalidJWTError, JWTRefreshError, UsernameMismatchError, UserNotActiveError


class TestJWTHandler:
    """Tests for the `JWTHandler` class."""

    def mock_datetime_now(self) -> datetime:
        """
        Mock function to return a predefined datetime object.

        :return: Predefined datetime object.
        """
        return datetime(2024, 1, 17, 10, 0, 0, 0, tzinfo=timezone.utc)

    @patch("ldap_jwt_auth.auth.jwt_handler.datetime")
    def test_get_access_token(self, datetime_mock):
        """
        Test getting an access token.
        """
        datetime_mock.now.return_value = self.mock_datetime_now()

        jwt_handler = JWTHandler()
        access_token = jwt_handler.get_access_token("username")

        assert access_token == EXPECTED_ACCESS_TOKEN

    @patch("ldap_jwt_auth.auth.jwt_handler.datetime")
    def test_get_refresh_token(self, datetime_mock):
        """
        Test getting a refresh token.
        """
        datetime_mock.now.return_value = self.mock_datetime_now()

        jwt_handler = JWTHandler()
        refresh_token = jwt_handler.get_refresh_token("username")

        assert refresh_token == EXPECTED_REFRESH_TOKEN

    @patch("ldap_jwt_auth.auth.jwt_handler.Authorisation.is_active_user")
    @patch("ldap_jwt_auth.auth.jwt_handler.datetime")
    def test_refresh_access_token(self, datetime_mock, is_active_user_mock):
        """
        Test refreshing an expired access token with a valid refresh token.
        """
        datetime_mock.now.return_value = self.mock_datetime_now()
        is_active_user_mock.return_value = True

        jwt_handler = JWTHandler()
        access_token = jwt_handler.refresh_access_token(EXPIRED_ACCESS_TOKEN, VALID_REFRESH_TOKEN)

        assert access_token == EXPECTED_ACCESS_TOKEN

    @patch("ldap_jwt_auth.auth.jwt_handler.Authorisation.is_active_user")
    def test_refresh_access_token_with_non_matching_usernames(self, is_active_user_mock):
        """
        Test refreshing an access token when the usernames in the access and refresh tokens do not match.
        """
        is_active_user_mock.return_value = True
        access_token = (
            "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InVzZXIxMjMiLCJyb2xlIjoiZGVmYXVsdCIsInVzZXJJc0FkbWluI"
            "jpmYWxzZSwiZXhwIjotNjIxMzU1OTY4MDB9.U3X2jOHNZESMa6BmaAFmXEukPI8KFmV777GsEXvNboC47ww-MnslmHWW6uRyMiYbuUZtaC"
            "2wMP-654j3GcLQdlPYfMmXFAymtGXchaGYQe6dDsd_9cqA-Iozypp3lUhMfr1JiVVPib7tecYGI-BebaeVxt-bfDhRCVE8rfSghWEI1VJ4"
            "glLbpkwRwOuIsjfZ4fZ7wepxOAQl89n8KmTsXKGc25gEEXO6wQVbxGMnFwH5XkvbjRY0XEMwZGPrSAf3sz6jvd60fTv715n3heP7eyH82V"
            "RGr4TcgwZILwNMwUXeXL9B_Lbq2--_VCKumYfb54jaiYI5iIYqrwy8XDK3Dg"
        )

        jwt_handler = JWTHandler()
        with pytest.raises(JWTRefreshError) as exc:
            jwt_handler.refresh_access_token(access_token, VALID_REFRESH_TOKEN)
        assert str(exc.value) == "Unable to refresh access token"
        assert isinstance(exc.value.__cause__, UsernameMismatchError)
        assert str(exc.value.__cause__) == "The usernames in the access and refresh tokens do not match"

    @patch("ldap_jwt_auth.auth.jwt_handler.Authorisation.is_active_user")
    def test_refresh_access_token_with_not_active_username(self, is_active_user_mock):
        """
        Test refreshing an access token when username is not active.
        """
        is_active_user_mock.return_value = False

        jwt_handler = JWTHandler()
        with pytest.raises(JWTRefreshError) as exc:
            jwt_handler.refresh_access_token(EXPIRED_ACCESS_TOKEN, VALID_REFRESH_TOKEN)
        assert str(exc.value) == "Unable to refresh access token"
        assert isinstance(exc.value.__cause__, UserNotActiveError)
        assert str(exc.value.__cause__) == "The provided username 'username' is not part of the active usernames"

    @patch("ldap_jwt_auth.auth.jwt_handler.Authorisation.is_active_user")
    @patch("ldap_jwt_auth.auth.jwt_handler.datetime")
    def test_refresh_access_token_with_valid_access_token(self, datetime_mock, is_active_user_mock):
        """
        Test refreshing a valid access token with a valid refresh token.
        """
        datetime_mock.now.return_value = self.mock_datetime_now()
        is_active_user_mock.return_value = True

        jwt_handler = JWTHandler()
        access_token = jwt_handler.refresh_access_token(VALID_ACCESS_TOKEN, VALID_REFRESH_TOKEN)

        assert access_token == EXPECTED_ACCESS_TOKEN

    def test_refresh_access_token_with_invalid_access_token(self):
        """
        Test refreshing an invalid access token with a valid refresh token.
        """
        jwt_handler = JWTHandler()

        with pytest.raises(JWTRefreshError) as exc:
            jwt_handler.refresh_access_token("invalid", VALID_REFRESH_TOKEN)
        assert str(exc.value) == "Unable to refresh access token"

    def test_refresh_access_token_with_expired_refresh_token(self):
        """
        Test refreshing an expired access token with an expired refresh token.
        """
        jwt_handler = JWTHandler()

        with pytest.raises(InvalidJWTError) as exc:
            jwt_handler.refresh_access_token(EXPIRED_ACCESS_TOKEN, EXPIRED_REFRESH_TOKEN)
        assert str(exc.value) == "Invalid JWT token"

    def test_verify_token_with_access_token(self):
        """
        Test verifying a valid access token.
        """
        jwt_handler = JWTHandler()
        payload = jwt_handler.verify_token(VALID_ACCESS_TOKEN)

        assert payload == {"username": "username", "role": "admin", "userIsAdmin": False, "exp": 253402300799}

    def test_verify_token_with_refresh_token(self):
        """
        Test verifying a valid refresh token.
        """
        jwt_handler = JWTHandler()
        payload = jwt_handler.verify_token(VALID_REFRESH_TOKEN)

        assert payload == {"username": "username", "exp": 253402300799}

    def test_verify_token_with_expired_access_token(self):
        """
        Test verifying an expired access token.
        """
        jwt_handler = JWTHandler()

        with pytest.raises(InvalidJWTError) as exc:
            jwt_handler.verify_token(EXPIRED_ACCESS_TOKEN)
        assert str(exc.value) == "Invalid JWT token"

    def test_verify_token_with_expired_refresh_token(self):
        """
        Test verifying an expired refresh token.
        """
        jwt_handler = JWTHandler()

        with pytest.raises(InvalidJWTError) as exc:
            jwt_handler.verify_token(EXPIRED_REFRESH_TOKEN)
        assert str(exc.value) == "Invalid JWT token"

    def test_verify_token_with_invalid_token(self):
        """
        Test verifying an invalid access token.
        """
        jwt_handler = JWTHandler()

        with pytest.raises(InvalidJWTError) as exc:
            jwt_handler.verify_token("invalid")
        assert str(exc.value) == "Invalid JWT token"
