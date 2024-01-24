# pylint: disable=no-member
"""
Unit tests for the `Authentication` class.
"""
from unittest.mock import Mock, patch

import ldap
import pytest
from ldap.ldapobject import LDAPObject

from ldap_jwt_auth.auth.authentication import Authentication
from ldap_jwt_auth.core.config import config
from ldap_jwt_auth.core.exceptions import (
    InvalidCredentialsError,
    LDAPServerError,
    UserNotActiveError,
    ActiveUsernamesFileNotFoundError,
)
from ldap_jwt_auth.core.schemas import UserCredentialsPostRequestSchema


@patch("ldap_jwt_auth.auth.authentication.ldap.initialize")
def test_authenticate(ldap_initialize_mock):
    """
    Test LDAP authentication with valid credentials.
    """
    ldap_obj_mock = Mock(LDAPObject)
    ldap_obj_mock.simple_bind_s.return_value = (97, [], 2, [])
    ldap_initialize_mock.return_value = ldap_obj_mock

    authentication = Authentication()
    user_credentials = UserCredentialsPostRequestSchema(username="username", password="password")
    authentication.authenticate(user_credentials)

    ldap_initialize_mock.assert_called_once_with(config.ldap_server.url)
    ldap_obj_mock.start_tls_s.assert_called_once()
    ldap_obj_mock.simple_bind_s.assert_called_once_with(
        f"{user_credentials.username}@{config.ldap_server.realm}", user_credentials.password
    )
    ldap_obj_mock.unbind.assert_called_once()


def test_authenticate_with_empty_credentials():
    """
    Test LDAP authentication with empty credentials.
    """
    authentication = Authentication()
    user_credentials = UserCredentialsPostRequestSchema(username="", password="")

    with pytest.raises(InvalidCredentialsError) as exc:
        authentication.authenticate(user_credentials)
    assert str(exc.value) == "Empty username or password"


@patch("ldap_jwt_auth.auth.authentication.ldap.initialize")
def test_authenticate_with_invalid_credentials(ldap_initialize_mock):
    """
    Test LDAP authentication with invalid credentials.
    """
    ldap_obj_mock = Mock(LDAPObject)
    ldap_obj_mock.simple_bind_s.side_effect = ldap.INVALID_CREDENTIALS
    ldap_initialize_mock.return_value = ldap_obj_mock

    authentication = Authentication()
    user_credentials = UserCredentialsPostRequestSchema(username="username", password="password")

    with pytest.raises(InvalidCredentialsError) as exc:
        authentication.authenticate(user_credentials)
    assert str(exc.value) == "Invalid username or password"
    ldap_initialize_mock.assert_called_once_with(config.ldap_server.url)
    ldap_obj_mock.start_tls_s.assert_called_once()
    ldap_obj_mock.simple_bind_s.assert_called_once_with(
        f"{user_credentials.username}@{config.ldap_server.realm}", user_credentials.password
    )
    ldap_obj_mock.unbind.assert_called_once()


def test_authenticate_with_not_active_username():
    """
    Test LDAP authentication with username that is not active.
    """
    authentication = Authentication()
    username = "username_not_active"
    user_credentials = UserCredentialsPostRequestSchema(username=username, password="password")

    with pytest.raises(UserNotActiveError) as exc:
        authentication.authenticate(user_credentials)
    assert str(exc.value) == f"The provided username '{username}' is not part of the active usernames"


@patch("ldap_jwt_auth.auth.authentication.ldap.initialize")
def test_authenticate_ldap_server_error(ldap_initialize_mock):
    """
    Test LDAP authentication when server error occurs.
    """
    ldap_obj_mock = Mock(LDAPObject)
    ldap_obj_mock.start_tls_s.side_effect = ldap.LDAPError
    ldap_initialize_mock.return_value = ldap_obj_mock

    authentication = Authentication()
    user_credentials = UserCredentialsPostRequestSchema(username="username", password="password")

    with pytest.raises(LDAPServerError) as exc:
        authentication.authenticate(user_credentials)
    assert str(exc.value) == "Problem with LDAP server"
    ldap_initialize_mock.assert_called_once_with(config.ldap_server.url)
    ldap_obj_mock.start_tls_s.assert_called_once()
    ldap_obj_mock.unbind.assert_not_called()


def test_is_user_active():
    """
    Test `is_user_active` returns `True` when active username is passed to it.
    """
    authentication = Authentication()
    is_user_active = authentication.is_user_active("username")

    assert is_user_active is True


def test_is_user_active_with_not_active_username():
    """
    Test `is_user_active` returns `False` when username that is not active is passed to it.
    """
    authentication = Authentication()
    is_user_active = authentication.is_user_active("username_not_active")

    assert is_user_active is False


@patch("builtins.open")
def test_is_user_active_active_usernames_file_not_found(file_open_mock):
    """
    Test `is_user_active` when file containing active usernames cannot be found.
    """
    file_open_mock.side_effect = FileNotFoundError()

    with pytest.raises(ActiveUsernamesFileNotFoundError) as exc:
        authentication = Authentication()
        authentication.is_user_active("username_not_active")
    assert (
        str(exc.value)
        == f"Cannot find file containing active usernames with path: {config.authentication.active_usernames_path}"
    )
