"""
Module for providing a class for managing user authorisation.
"""

import yaml

from ldap_jwt_auth.core.config import config
from ldap_jwt_auth.core.exceptions import InvalidUserConfigFileError, UserConfigFileNotFoundError


class Authorisation:
    """
    Class for managing authorisation against user_config.yaml
    """

    def __init__(self) -> None:
        """
        Initialize the `Authorisation` class and load the user_config file
        """

        try:
            with open(config.authentication.users_config_path, "r", encoding="utf-8") as file:
                user_config = yaml.safe_load(file)
                self.roles = user_config.get("roles", {})
                self.users = user_config.get("users", {})

                if self.users == {} or self.roles == {}:
                    raise InvalidUserConfigFileError("Cannot parse user configuration file. Missing users or roles.")

        except FileNotFoundError as exc:
            raise UserConfigFileNotFoundError(
                f"Cannot find file containing users configuration with path: {config.authentication.users_config_path}"
            ) from exc
        except yaml.YAMLError as exc:
            raise InvalidUserConfigFileError(
                f"Cannot load user configuration file with path: {config.authentication.users_config_path}"
            ) from exc

    def is_active_user(self, identifier: str) -> bool:
        """
        Check if the provided username or email is a part of the active users username or email.

        :param identifier: The username or email to check.
        :return: `True` if the user is active, `False` otherwise
        """
        return self._find_user(identifier) is not None

    def get_user_role(self, identifier: str) -> str:
        """
        Get the provided user's role.

        :param identifier: The username or email to fetch for
        :return: `str` which is the defined role of the user, 'default' if no role
        """

        user = self._find_user(identifier)
        return user.get("role", "default") if user else "default"

    def is_user_admin(self, role: str) -> bool:
        """
        Check if the given user's role is a role with the highest privilege level
        defined in the configuration.

        :param role: The role for the given user
        :return: `True` if the user has a role which matches the role(s) with the highest privilege, `False` otherwise
        """

        if self.roles.get(role, {}).get("userIsAdmin", False):
            return True

        return False

    def _find_user(self, identifier: str) -> dict | None:
        """
        Find a user by username or email.

        :param identifier: The username or email to check.
        :return: The user as a dict if found, otherwise None.
        """
        for user in self.users:
            if user.get("username") == identifier or user.get("email") == identifier:
                return user
        return None
