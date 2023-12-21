"""
Module for providing a class for handling JWTs.
"""
import logging
from datetime import datetime, timezone, timedelta
from typing import Any, Dict

import jwt
from cryptography.hazmat.primitives import serialization

from ldap_jwt_auth.core.config import config
from ldap_jwt_auth.core.constants import PRIVATE_KEY, PUBLIC_KEY

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

    def get_refresh_token(self) -> str:
        """
        Generates a payload and returns a signed JWT refresh token.
        :return: The signed JWT refresh token.
        """
        logger.info("Getting a refresh token")
        payload = {
            "exp": datetime.now(timezone.utc) + timedelta(days=config.authentication.refresh_token_validity_days)
        }
        return self._pack_jwt(payload)

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
