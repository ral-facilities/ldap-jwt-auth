"""
Module for providing a class for handling JWTs.
"""
import logging
from datetime import datetime, timezone, timedelta

import jwt
from cryptography.hazmat.primitives import serialization

from ldap_jwt_auth.core.config import config
from ldap_jwt_auth.core.constants import PRIVATE_KEY

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

    def _pack_jwt(self, payload: dict) -> str:
        """
        Packs the provided payload into a JWT token and signs it.
        :param payload: The payload to be packed.
        :return: The encoded and signed JWT.
        """
        logger.debug("Packing payload into a JWT")
        bytes_key = bytes(PRIVATE_KEY, encoding="utf8")
        loaded_private_key = serialization.load_ssh_private_key(bytes_key, password=None)
        token = jwt.encode(payload, loaded_private_key, algorithm=config.authentication.jwt_algorithm)
        return token
