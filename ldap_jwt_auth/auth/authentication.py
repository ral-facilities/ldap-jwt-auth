"""
Module for providing a class for managing authentication.
"""
import logging

import ldap

from ldap_jwt_auth.core.config import config
from ldap_jwt_auth.core.exceptions import InvalidCredentialsError, LDAPServerError
from ldap_jwt_auth.core.models import UserCredentials

logger = logging.getLogger()


class Authentication:
    """
    Class for managing authentication against an LDAP server.
    """

    def authenticate(self, user_credentials: UserCredentials) -> None:
        """
        Authenticate a user against an LDAP server based on the provided user credentials.
        :param user_credentials: The credentials of the user.
        :raises InvalidCredentialsError: If the user credentials are invalid.
        :raises LDAPServerError: If there is a problem with the LDAP server.
        """
        username = user_credentials.username
        logger.info("Authenticating a user")
        logger.debug("Username provided is '%s'", username)

        try:
            connection = ldap.initialize(config.ldap_server.url)
            ldap.set_option(ldap.OPT_PROTOCOL_VERSION, 3)
            ldap.set_option(ldap.OPT_X_TLS_DEMAND, True)
            ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
            ldap.set_option(ldap.OPT_DEBUG_LEVEL, 0)
            connection.start_tls_s()
            connection.simple_bind_s(f"{username}@{config.ldap_server.realm}", user_credentials.password)
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
