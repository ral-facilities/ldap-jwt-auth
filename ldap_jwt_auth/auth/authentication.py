# pylint: disable=no-member
"""
Module for providing a class for managing authentication.
"""
import logging

from cachetools.func import ttl_cache

import jwt
import ldap
import requests

from ldap_jwt_auth.auth.authorisation import Authorisation
from ldap_jwt_auth.core.config import OIDCProviderConfig, config
from ldap_jwt_auth.core.exceptions import (
    InvalidCredentialsError,
    LDAPServerError,
    UserNotActiveError,
    OIDCProviderNotFoundError,
    OIDCProviderError,
    InvalidJWTError,
)
from ldap_jwt_auth.core.schemas import UserCredentialsPostRequestSchema

logger = logging.getLogger()


class LDAPAuthentication:
    """
    Class for managing authentication against an LDAP server.
    """

    def __init__(self) -> None:
        self._authorisation = Authorisation()

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

        if not self._authorisation.is_active_user(username):
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


class OIDCAuthentication:
    """
    Class for managing authentication against an OIDC provider.
    """

    def __init__(self) -> None:
        self._authorisation = Authorisation()

    def authenticate(self, provider_id: str, id_token: str) -> str:
        """
        Authenticate a user by verifying the provided OIDC ID token using the JWKs of the specified OIDC provider.

        After the verification succeeds, it checks that the username claim specified in the configuration is not missing
        and that the username is part of the active user emails.

        :param provider_id: The ID of the OIDC provider to get the corresponding configuration for.
        :param id_token: The provided OIDC token to verify using the JWKs of the specified OIDC provider.
        :raises InvalidJWTError: If the username claim specified in the configuration is missing in the OIDC ID token.
        :raises UserNotActiveError: If the username is not part of the active user emails.
        :raises InvalidJWTError: If the OIDC ID token is invalid.
        :return: The username.
        """
        provider_config = _get_oidc_provider_config(provider_id)

        try:
            unverified_header = jwt.get_unverified_header(id_token)
            kid = unverified_header["kid"]
            well_known_config = _get_well_known_config(provider_id)
            key = _get_jwks(provider_id, well_known_config["jwks_uri"])[kid]

            # Ensure that this key can be used for signing
            if key.public_key_use not in [None, "sig"]:
                raise InvalidJWTError("Invalid OIDC ID token")

            payload = jwt.decode(
                jwt=id_token,
                key=key,
                algorithms=[key.algorithm_name],
                audience=provider_config.client_id,
                issuer=well_known_config["issuer"],
                verify=True,
                options={"require": ["exp", "aud", "iss"], "verify_exp": True, "verify_aud": True, "verify_iss": True},
                # Amount of leeway (in seconds) when validating exp & iat
                leeway=5,
            )

            username = payload.get(provider_config.username_claim)
            if not username:
                raise InvalidJWTError("Username claim missing in OIDC ID token")

            if not self._authorisation.is_active_user(username):
                raise UserNotActiveError(f"The provided email '{username}' is not part of the active user emails")

            return username

        except (jwt.exceptions.ExpiredSignatureError, jwt.exceptions.InvalidTokenError, KeyError) as exc:
            raise InvalidJWTError("Invalid OIDC ID token") from exc


def _get_oidc_provider_config(provider_id: str) -> OIDCProviderConfig:
    """
    Get the configuration for the OIDC provider using the specified `provider_id` from the config.

    :param provider_id: The ID of the OIDC provider to get the configuration for.
    :raises OIDCProviderNotFoundError: If no configuration can be found for the specified OIDC provider.
    :return:
    """
    try:
        return config.oidc_providers[provider_id]
    except KeyError as exc:
        raise OIDCProviderNotFoundError(f"No configuration found for OIDC provider: {provider_id}") from exc


@ttl_cache(ttl=2 * 60 * 60)
def _get_jwks(provider_id: str, jwks_uri: str) -> jwt.PyJWKSet:
    """
    Fetch the JWKs for the specified OIDC provider.

    :param provider_id: The ID of the OIDC provider to fetch the JWKs for.
    :param jwks_uri: The URI to the JWKs.
    :raises OIDCProviderError: If it fails to fetch the JWKs.
    :return: The JWKs for the specified OIDC provider.
    """
    provider_config = _get_oidc_provider_config(provider_id)

    try:
        r = requests.get(jwks_uri, verify=provider_config.verify_cert, timeout=provider_config.request_timeout_seconds)
        r.raise_for_status()
        jwks_config = r.json()
    except Exception as exc:
        raise OIDCProviderError(f"Failed to fetch JWKs for OIDC provider: {provider_id}") from exc

    return jwt.PyJWKSet(jwks_config["keys"])


@ttl_cache(ttl=24 * 60 * 60)
def _get_well_known_config(provider_id: str) -> dict:
    """
    Fetch the well known configuration for the specified OIDC provider.

    :param provider_id: The ID of the OIDC provider to fetch the well known configuration for.
    :raises OIDCProviderError: If it fails to fetch the well known configuration.
    :return: The well known configuration for the specified OIDC provider.
    """
    provider_config = _get_oidc_provider_config(provider_id)

    try:
        r = requests.get(
            provider_config.configuration_url,
            verify=provider_config.verify_cert,
            timeout=provider_config.request_timeout_seconds,
        )
        r.raise_for_status()
        return r.json()
    except Exception as exc:
        raise OIDCProviderError(f"Failed to fetch well known configuration for OIDC provider: {provider_id}") from exc
