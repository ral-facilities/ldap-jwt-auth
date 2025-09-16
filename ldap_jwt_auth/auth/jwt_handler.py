"""
Module for providing a class for handling JWTs.
"""

import logging
from datetime import datetime, timezone, timedelta
from typing import Any, Dict

import jwt
from cryptography.hazmat.primitives import serialization

from ldap_jwt_auth.auth.authentication import LDAPAuthentication, OIDCAuthentication
from ldap_jwt_auth.core.config import config
from ldap_jwt_auth.core.constants import PRIVATE_KEY, PUBLIC_KEY
from ldap_jwt_auth.core.exceptions import InvalidJWTError, JWTRefreshError, UserNotActiveError, UsernameMismatchError

logger = logging.getLogger()


class JWTHandler:
    """
    Class for handling JWTs.
    """

    def get_access_token(self, username: str) -> str:
        """
        Generates a payload and returns a signed JWT access token.

        :param username: The username of the user.
        :return: The signed JWT access token
        """
        logger.info("Getting an access token")
        payload = {
            "username": username,
            "exp": datetime.now(timezone.utc) + timedelta(minutes=config.authentication.access_token_validity_minutes),
        }
        return self._pack_jwt(payload)

    def get_refresh_token(self, username: str) -> str:
        """
        Generates a payload and returns a signed JWT refresh token.

        :param username: The username of the user.
        :return: The signed JWT refresh token.
        """
        logger.info("Getting a refresh token")
        payload = {
            "username": username,
            "exp": datetime.now(timezone.utc) + timedelta(days=config.authentication.refresh_token_validity_days),
        }
        return self._pack_jwt(payload)

    def refresh_access_token(self, access_token: str, refresh_token: str) -> str:
        """
        Refreshes the JWT access token by updating its expiry time, provided that the JWT refresh token is valid.

        Before attempting to refresh the token, it checks that the usernames in the access and refresh tokens match, and
        that the username is still part of the active usernames.

        :param access_token: The JWT access token to refresh.
        :param refresh_token: The JWT refresh token.
        :raises JWTRefreshError: If the JWT access token cannot be refreshed.
        :raises UsernameMismatchError: If the usernames in the access and refresh tokens do not match
        :raises UserNotActiveError: If the username is no longer part of the active usernames.
        :return: JWT access token with an updated expiry time.
        """
        logger.info("Refreshing access token")
        refresh_token_payload = self.verify_token(refresh_token)

        try:
            access_token_payload = self._get_jwt_payload(access_token, {"verify_exp": False})
            username = access_token_payload["username"]

            if username != refresh_token_payload["username"]:
                raise UsernameMismatchError("The usernames in the access and refresh tokens do not match")

            if not self._is_user_active(username):
                raise UserNotActiveError(f"The provided username '{username}' is not part of the active usernames")

            access_token_payload["exp"] = datetime.now(timezone.utc) + timedelta(
                minutes=config.authentication.access_token_validity_minutes
            )
            return self._pack_jwt(access_token_payload)
        except Exception as exc:
            message = "Unable to refresh access token"
            logger.exception(message)
            raise JWTRefreshError(message) from exc

    def verify_token(self, token: str) -> Dict[str, Any]:
        """
        Verifies that the provided JWT token is valid. It does this by checking that it was signed by the corresponding
        private key and has not expired.

        :param token: The JWT token to be verified.
        :raises InvalidJWTError: If the JWT token is invalid.
        :return: The payload of the verified JWT token.
        """
        logger.info("Verifying JWT token is valid")
        try:
            return self._get_jwt_payload(token)
        except Exception as exc:
            message = "Invalid JWT token"
            logger.exception(message)
            raise InvalidJWTError(message) from exc

    def _is_user_active(self, username: str) -> bool:
        """
        Checks if the provided username is active. If the username contains an '@' and '.' charcaters then it should be
        checked against the list of OIDC active user emails as the user was authenticated through OIDC. If this is not
        the case then it should be checked against the list of LPDA active usernames.

        :param username: The username to check.
        :return: `True` if the user is active, `False` otherwise.  
        """

        if "@" in username and "." in username:
            oidc_authentication = OIDCAuthentication()
            return oidc_authentication.is_user_active(username)

        ldap_authentication = LDAPAuthentication()
        return ldap_authentication.is_user_active(username)

    def _get_jwt_payload(self, token: str, jwt_decode_options: dict | None = None) -> Dict[str, Any]:
        """
        Decodes the provided JWT token and gets its payload.

        :param token: The JWT token to decode and get payload from.
        :param jwt_decode_options: Any options to be passed to the `decode` method.
        :return: Payload from the provided JWT token.
        """
        logger.info("Decoding JWT token")
        return jwt.decode(
            token, PUBLIC_KEY, algorithms=[config.authentication.jwt_algorithm], options=jwt_decode_options
        )

    def _pack_jwt(self, payload: dict) -> str:
        """
        Packs the provided payload into a JWT token and signs it.

        :param payload: The payload to be packed.
        :return: The encoded and signed JWT token.
        """
        logger.debug("Packing payload into a JWT token")
        bytes_key = bytes(PRIVATE_KEY, encoding="utf8")
        loaded_private_key = serialization.load_ssh_private_key(bytes_key, password=None)
        return jwt.encode(payload, loaded_private_key, algorithm=config.authentication.jwt_algorithm)
