"""
Unit tests for the `Authorisation` class.
"""

from unittest.mock import patch
import pytest
import yaml

from ldap_jwt_auth.auth.authorisation import Authorisation
from ldap_jwt_auth.core.config import config
from ldap_jwt_auth.core.exceptions import InvalidUserConfigFileError, UserConfigFileNotFoundError


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
    Test when file containing active users cannot be found.
    """
    file_open_mock.side_effect = FileNotFoundError()

    with pytest.raises(UserConfigFileNotFoundError) as exc:
        Authorisation()
    assert (
        str(exc.value)
        == f"Cannot find file containing users configuration with path: {config.authentication.users_config_path}"
    )


@patch("yaml.safe_load")
def test_invalid_user_config_file_error(yaml_load_mock):
    """
    Test when the user config file is present but contains invalid YAML.
    """
    yaml_load_mock.side_effect = yaml.YAMLError("Invalid YAML")

    with pytest.raises(InvalidUserConfigFileError) as exc:
        Authorisation()
    assert str(exc.value) == f"Cannot load user configuration file with path: {config.authentication.users_config_path}"


def test_get_user_roles():
    """
    Test `get_user_roles` returns the correct roles for a given username.
    """
    authorisation = Authorisation()
    user_roles = authorisation.get_user_roles("username")

    assert user_roles == ["admin"]


def test_is_user_admin():
    """
    Test `is_user_admin` for roles which include highest privilege role
    """
    authorisation = Authorisation()
    is_user_admin = authorisation.is_user_admin(["admin", "moderator"])

    assert is_user_admin is True


def test_is_user_admin_non_existent_roles():
    """
    Test `is_user_admin` for roles which do not exist in the config
    """
    authorisation = Authorisation()
    is_user_admin = authorisation.is_user_admin(["invalid", "does_not_exist"])

    assert is_user_admin is False
