"""
Module for for providing a class for managing user authorisation
"""

import yaml

from ldap_jwt_auth.core.config import config
from ldap_jwt_auth.core.exceptions import UserConfigFileNotFoundError, UserNotActiveError


class Authorisation:
    """
    Class for managing authorisation against user_config.yaml
    """

    def __init__(self) -> None:
        """
        Initialize the `Authorisation` class and load the user_config file
        """

        try:
            with open(config.authentication.user_config_path, "r", encoding="utf-8") as file:
                user_config = yaml.safe_load(file)
                self.roles = user_config.get("roles", {})
                self.users = user_config.get("users", {})

        except FileNotFoundError as exc:
            raise UserConfigFileNotFoundError(
                f"Cannot find file containing users configuration with path: {config.authentication.user_config_path}"
            ) from exc

    def is_active_user(self, username: str) -> bool:
        """
        Check if the provided username is a part of the active usernames.
        :param username: The username to check.
        :return `True` if the user is active, `False` otherwise
        """
        return username in self.users

    def get_user_roles(self, username: str) -> list[str]:
        """
        Get the provided username's roles
        :param username: The username to fetch for
        :return `List[str]` containing the defined roles of the user, can be an empty list
        """
        if not self.is_active_user(username):
            raise UserNotActiveError(f"The provided username '{username}' is not part of the active usernames")

        return self.users.get(username, {}).get("roles", [])

    def is_user_admin(self, roles: list[str]) -> bool:
        """
        Check if the given user's roles hold at least one role with the highest privilege level 
        defined in the configuration.
        param: roles: The list of roles for the given user
        return `True` if the user has any role which matches the role(s) with the highest privilege, `False` otherwise
        """
        for role in roles:
            if self.roles.get(role, {}).get("userIsAdmin", False):
                return True
        return False
