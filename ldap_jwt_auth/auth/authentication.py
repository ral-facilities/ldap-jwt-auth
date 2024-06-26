# pylint: disable=no-member
"""
Module for providing a class for managing authentication.
"""
import logging

import ldap

from ldap_jwt_auth.core.config import config
from ldap_jwt_auth.core.exceptions import (
    InvalidCredentialsError,
    LDAPServerError,
    ActiveUsernamesFileNotFoundError,
    UserNotActiveError,
)
from ldap_jwt_auth.core.schemas import UserCredentialsPostRequestSchema

logger = logging.getLogger()


class Authentication:
    """
    Class for managing authentication against an LDAP server.
    """

    def authenticate(self, user_credentials: UserCredentialsPostRequestSchema) -> None:
        """
        Authenticate a user against an LDAP server based on the provided user credentials.

        Before attempting to authenticate against LDAP, it checks that the credentials are not empty and that the
        username is part of the active usernames.
        :param user_credentials: The credentials of the user.
        :raises InvalidCredentialsError: If the user credentials are empty or invalid.
        :raises LDAPServerError: If there is a problem with the LDAP server.
        :raises UserNotActiveError: If the username is not part of the active usernames.
        """
        username = user_credentials.username.get_secret_value()
        password = user_credentials.password.get_secret_value()
        logger.info("Authenticating a user")
        logger.debug("Username provided is '%s'", username)

        if not username or not password:
            raise InvalidCredentialsError("Empty username or password")

        if not self.is_user_active(username):
            raise UserNotActiveError(f"The provided username '{username}' is not part of the active usernames")

        try:
            # Disable LDAP operations debugging
            ldap.set_option(ldap.OPT_DEBUG_LEVEL, 0)

            connection = ldap.initialize(config.ldap_server.url.get_secret_value())
            # Set version of LDAP in use
            connection.protocol_version = ldap.VERSION3
            if config.ldap_server.certificate_validation is True:
                # Force certificate validation
                connection.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_DEMAND)
                # Set file containing all trusted CA certificates
                connection.set_option(ldap.OPT_X_TLS_CACERTFILE, config.ldap_server.ca_certificate_file_path)
            else:
                # Do not validate certificate
                connection.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)

            # Force creation of new SSL context (must be last TLS option)
            connection.set_option(ldap.OPT_X_TLS_NEWCTX, 0)

            if not config.ldap_server.url.get_secret_value().startswith("ldaps://"):
                # Upgrade connection to a secure TLS session
                connection.start_tls_s()

            connection.simple_bind_s(f"{username}@{config.ldap_server.realm.get_secret_value()}", password)
            logger.info("Authentication successful")
            connection.unbind()
        except ldap.INVALID_CREDENTIALS as exc:
            message = "Invalid username or password"
            logger.exception(message)
            connection.unbind()
            raise InvalidCredentialsError(message) from exc
        except Exception as exc:
            message = "Problem with LDAP server"
            logger.exception(message)
            raise LDAPServerError(message) from exc

    def is_user_active(self, username: str) -> bool:
        """
        Check if the provided username is part of the active usernames.
        :param username: The username to check.
        :return: `True` if the user is active, `False` otherwise.
        """
        logger.info("Checking if user is active")
        active_usernames = self._get_active_usernames()
        return username in active_usernames

    def _get_active_usernames(self) -> list:
        """
        Load the active usernames as a list from a `txt` file. It removes any leading and trailing whitespaces and does
        not load empty lines/strings.
        :return: The list of active usernames.
        :raises ActiveUsernamesFileNotFoundError: If the file containing the active usernames cannot be found.
        """
        try:
            with open(config.authentication.active_usernames_path, "r", encoding="utf-8") as file:
                return [line.strip() for line in file.readlines() if line.strip()]
        except FileNotFoundError as exc:
            raise ActiveUsernamesFileNotFoundError(
                f"Cannot find file containing active usernames with path: {config.authentication.active_usernames_path}"
            ) from exc
