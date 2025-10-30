"""
Unit tests for the `Authorisation` class.
"""

from unittest.mock import patch
import pytest
import yaml

from ldap_jwt_auth.auth.authorisation import Authorisation
from ldap_jwt_auth.core.config import config
from ldap_jwt_auth.core.exceptions import InvalidUserConfigFileError, UserConfigFileNotFoundError


class TestAuthorisation:
    """Tests for the `Authorisation` class."""

    def test_is_active_user(self):
        """
        Test `is_active_user` returns `True` when active username is passed to it.
        """
        authorisation = Authorisation()
        is_active_user = authorisation.is_active_user("username")

        assert is_active_user is True

    def test_is_active_user_with_not_active_username(self):
        """
        Test `is_active_user` returns `False` when username that is not active is passed to it.
        """
        authorisation = Authorisation()
        is_active_user = authorisation.is_active_user("username_not_active")

        assert is_active_user is False

    @patch("builtins.open")
    def test_user_config_file_not_found(self, file_open_mock):
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
    def test_invalid_user_config_file_error(self, yaml_load_mock):
        """
        Test when the user config file is present but contains invalid YAML.
        """
        yaml_load_mock.side_effect = yaml.YAMLError("Invalid YAML")

        with pytest.raises(InvalidUserConfigFileError) as exc:
            Authorisation()
        assert (
            str(exc.value)
            == f"Cannot load user configuration file with path: {config.authentication.users_config_path}"
        )

    @patch("yaml.safe_load")
    def test_invalid_user_config_file_missing_users(self, yaml_load_mock):
        """
        Test InvalidUserConfigFileError is raised if users is an empty dict.
        """

        yaml_load_mock.return_value = {"roles": {"admin": {"userIsAdmin": True}}, "users": {}}
        with pytest.raises(InvalidUserConfigFileError) as exc:
            Authorisation()
        assert str(exc.value) == "Cannot parse user configuration file. Missing users or roles."

    @patch("yaml.safe_load")
    def test_invalid_user_config_file_missing_roles(self, yaml_load_mock):
        """
        Test InvalidUserConfigFileError is raised if roles is an empty dict.
        """

        yaml_load_mock.return_value = {"roles": {}, "users": [{"username": "user1"}]}
        with pytest.raises(InvalidUserConfigFileError) as exc:
            Authorisation()
        assert str(exc.value) == "Cannot parse user configuration file. Missing users or roles."

    def test_get_user_role(self):
        """
        Test `get_user_role` returns the correct role for a given username.
        """
        authorisation = Authorisation()
        user_role = authorisation.get_user_role("username")

        assert user_role == "admin"

    def test_is_user_scigateway_admin(self):
        """
        Test `is_user_scigateway_admin` for role which has `userIsAdmin` set to true
        """
        authorisation = Authorisation()
        is_user_scigateway_admin = authorisation.is_user_scigateway_admin("scigateway-admin")

        assert is_user_scigateway_admin is True

    def test_is_user_scigateway_admin_non_existent_role(self):
        """
        Test `is_user_scigateway_admin` for role which does not exist in the config
        """
        authorisation = Authorisation()
        is_user_scigateway_admin = authorisation.is_user_scigateway_admin("invalid")

        assert is_user_scigateway_admin is False
