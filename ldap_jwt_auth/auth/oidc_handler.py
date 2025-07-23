import logging

import jwt
import requests

from ldap_jwt_auth.core.config import config
from ldap_jwt_auth.core.exceptions import OIDCServerError, ActiveUserEmailsFileNotFoundError, UserNotActiveError

logger = logging.getLogger()


class OIDCProvider:

    def __init__(self, config_url: str, audience: str, verify_cert: bool, username_claim: str) -> None:
        self._audience = audience
        self._username_claim = username_claim

        try:
            # Read discovery
            r = requests.get(config_url, verify=verify_cert)
            r.raise_for_status()
            oidc_config = r.json()
            self._issuer = oidc_config["issuer"]
        except Exception as exc:
            message = "Failed to fetch discovery from OIDC server"
            logger.exception(message)
            raise OIDCServerError(message) from exc

        try:
            # Read keys
            jwks_uri = oidc_config["jwks_uri"]
            r = requests.get(jwks_uri, verify=verify_cert)
            r.raise_for_status()
            jwks_config = r.json()
        except Exception as exc:
            message = "Failed to fetch JWKS from OIDC server"
            logger.exception(message)
            raise OIDCServerError(message) from exc

        self._keys = {}
        for key in jwks_config["keys"]:
            kid = key["kid"]
            try:
                self._keys[kid] = jwt.PyJWK(key)
            except jwt.exceptions.PyJWKError:
                # Possibly unsupported algorithm (e.g. RSA-OAEP)
                pass

    def get_audience(self) -> str:
        return self._audience

    def get_issuer(self) -> str:
        return self._issuer

    def get_key(self, kid: str) -> jwt.PyJWK:
        return self._keys[kid]

    def get_username_claim(self) -> str:
        return self._username_claim


class OidcHandler:

    def __init__(self) -> None:
        self._providers = {}
        for provider in config.oidc_providers.values():
            p = OIDCProvider(
                provider.configuration_url, provider.audience, provider.verify_cert, provider.username_claim
            )
            self._providers[p.get_issuer()] = p

    def handle(self, encoded_token: str):
        try:
            unverified_header = jwt.get_unverified_header(encoded_token)
            unverified_payload = jwt.decode(encoded_token, options={"verify_signature": False})

            kid = unverified_header["kid"]
            iss = unverified_payload["iss"]
            provider = self._providers[iss]
            key = provider.get_key(kid)

            payload = jwt.decode(
                encoded_token,
                key=key,
                algorithms=[key.algorithm_name],
                audience=provider.get_audience(),
                options={"require": ["exp", "aud"], "verify_exp": True, "verify_aud": True},
            )

            username_claim = payload.get(provider.get_username_claim())
            if not username_claim:
                raise OIDCServerError("Username claim missing in ID token")

            if not self.is_user_active(username_claim):
                raise UserNotActiveError(f"The provided email '{username_claim}' is not part of the active user emails")

            return username_claim

        except jwt.exceptions.ExpiredSignatureError as exc:
            message = "Expired OIDC ID token"
            logger.exception(message)
            raise OIDCServerError(message) from exc

        except jwt.exceptions.InvalidTokenError as exc:
            message = "Expired OIDC ID token"
            logger.exception(message)
            raise OIDCServerError(message) from exc

    def is_user_active(self, user_email: str) -> bool:
        """
        Check if the provided email is part of the active user emails.

        :param user_email: The email to check.
        :return: `True` if the user is active, `False` otherwise.
        """
        logger.info("Checking if user is active")
        active_user_emails = self._get_active_user_emails()
        return user_email in active_user_emails

    def _get_active_user_emails(self) -> list:
        """
        Load the emails of the active users as a list from a `txt` file. It removes any leading and trailing whitespaces
        and does not load empty lines/strings.

        :return: The list of emails of the active users.
        :raises ActiveUsernamesFileNotFoundError: If the file containing the emails of the active users cannot be found.
        """
        try:
            with open(config.authentication.active_user_emails_path, "r", encoding="utf-8") as file:
                return [line.strip() for line in file.readlines() if line.strip()]
        except FileNotFoundError as exc:
            raise ActiveUserEmailsFileNotFoundError(
                f"Cannot find file containing emails of active users with path: {config.authentication.active_user_emails_path}"
            ) from exc
