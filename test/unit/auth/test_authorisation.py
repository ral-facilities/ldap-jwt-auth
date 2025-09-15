
"""
Unit tests for the `Authorisation` class.
"""

from unittest.mock import patch
import pytest

from ldap_jwt_auth.auth.authorisation import Authorisation
from ldap_jwt_auth.core.config import config
from ldap_jwt_auth.core.exceptions import UserConfigFileNotFoundError, UserNotActiveError


def test_is_active_user():
    """
    Test `is_active_user` returns `True` when active username is passed to it.
    """
    authorisation = Authorisation()
    is_active_user = authorisation.is_active_user("username")

    assert is_active_user is True


def test_is_active_user_with_not_active_username():
    """
    Test `is_active_user` returns `False` when username that is not active is passed to it.
    """
    authorisation = Authorisation()
    is_active_user = authorisation.is_active_user("username_not_active")

    assert is_active_user is False


@patch("builtins.open")
def test_user_config_file_not_found(file_open_mock):
    """
    Test `is_active_user` when file containing active usernames cannot be found.
    """
    file_open_mock.side_effect = FileNotFoundError()

    with pytest.raises(UserConfigFileNotFoundError) as exc:
        authorisation = Authorisation()
        authorisation.is_active_user("username_not_active")
    assert (
        str(exc.value)
        == f"Cannot find file containing users configuration with path: {config.authentication.user_config_path}"
    )


def test_get_user_roles():
    """
    Test `get_user_roles` returns the correct roles for a given username.
    """
    authorisation = Authorisation()
    user_roles = authorisation.get_user_roles('username')

    assert user_roles == ['admin']

def test_get_user_roles_for_non_active_user():
    """
    Test `get_user_roles` when searching for roles for a non-active username
    """

    

    with pytest.raises(UserNotActiveError) as exc:
        authorisation = Authorisation()
        authorisation.get_user_roles('username_not_active')
    assert (
        str(exc.value)
        == f"The provided username 'username_not_active' is not part of the active usernames"
    )

def test_is_user_admin():
    """
    Test `is_user_admin` for roles which include highest privilege role
    """
    authorisation = Authorisation()
    is_user_admin = authorisation.is_user_admin(['admin', 'moderator'])

    assert is_user_admin is True

def test_is_user_admin_non_existent_roles():
    """
    Test `is_user_admin` for roles which do not exist in the config
    """
    authorisation = Authorisation()
    is_user_admin = authorisation.is_user_admin(["invalid", "does_not_exist"])

    assert is_user_admin == False