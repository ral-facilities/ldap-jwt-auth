"""
Module for providing an API router which defines login route(s).
"""

import logging
from typing import Annotated

from fastapi import APIRouter, Body, Depends, HTTPException, status
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from ldap_jwt_auth.auth.authentication import LDAPAuthentication, OIDCAuthentication
from ldap_jwt_auth.auth.jwt_handler import JWTHandler
from ldap_jwt_auth.core.config import config
from ldap_jwt_auth.core.exceptions import (
    UserNotActiveError,
    UserConfigFileNotFoundError,
    InvalidCredentialsError,
    InvalidJWTError,
    LDAPServerError,
    OIDCProviderError,
    OIDCProviderNotFoundError,
)
from ldap_jwt_auth.core.schemas import UserCredentialsPostRequestSchema

logger = logging.getLogger()

router = APIRouter(tags=["authentication"])


@router.get(
    path="/oidc_providers",
    summary="Get a list of OIDC providers",
    response_description="Returns a list of OIDC providers",
)
def get_oidc_providers() -> JSONResponse:
    # pylint: disable=missing-function-docstring
    logger.info("Getting a list of OIDC providers")
    providers = {}
    for provider_id, provider_config in config.oidc_providers.items():
        providers[provider_id] = {
            "display_name": provider_config.display_name,
            "configuration_url": provider_config.configuration_url,
            "client_id": provider_config.client_id,
            "pkce": True,
            "scope": provider_config.scope,
        }

    return JSONResponse(content=providers)


@router.post(
    path="/oidc_login/{provider_id}",
    summary="Login with an OIDC ID token",
    response_description="A JWT access token including a refresh token as an HTTP-only cookie",
)
def oidc_login(
    provider_id: Annotated[str, "The OIDC provider ID"],
    bearer_token: Annotated[HTTPAuthorizationCredentials, Depends(HTTPBearer(description="OIDC ID token"))],
    jwt_handler: Annotated[JWTHandler, Depends(JWTHandler)],
    oidc_authentication: Annotated[OIDCAuthentication, Depends(OIDCAuthentication)],
) -> JSONResponse:
    # pylint: disable=missing-function-docstring
    logger.info("Authenticating a user using an OIDC ID token")

    id_token = bearer_token.credentials
    try:
        username = oidc_authentication.authenticate(provider_id, id_token)
        access_token = jwt_handler.get_access_token(username)
        refresh_token = jwt_handler.get_refresh_token(username)

        response = JSONResponse(content=access_token)
        response.set_cookie(
            key="refresh_token",
            value=refresh_token,
            max_age=config.authentication.refresh_token_validity_days * 24 * 60 * 60,
            secure=True,
            httponly=True,
            samesite="lax",
            path=f"{config.api.root_path}/refresh",
        )
        return response
    except (InvalidJWTError, UserNotActiveError) as exc:
        message = "Invalid OIDC ID token provided"
        logger.exception(message)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=message) from exc
    except OIDCProviderNotFoundError as exc:
        message = "OIDC provider not found"
        logger.exception(message)
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=message) from exc
    except (UserConfigFileNotFoundError, OIDCProviderError) as exc:
        message = "Something went wrong"
        logger.exception(message)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=message) from exc


@router.post(
    path="/login",
    summary="Login with a username and password",
    response_description="A JWT access token including a refresh token as an HTTP-only cookie",
)
def ldap_login(
    user_credentials: Annotated[UserCredentialsPostRequestSchema, Body(description="The credentials of the user")],
    ldap_authentication: Annotated[LDAPAuthentication, Depends(LDAPAuthentication)],
    jwt_handler: Annotated[JWTHandler, Depends(JWTHandler)],
) -> JSONResponse:
    # pylint: disable=missing-function-docstring
    logger.info("Authenticating a user using LDAP credentials")

    try:
        ldap_authentication.authenticate(user_credentials)
        access_token = jwt_handler.get_access_token(user_credentials.username.get_secret_value())
        refresh_token = jwt_handler.get_refresh_token(user_credentials.username.get_secret_value())

        response = JSONResponse(content=access_token)
        response.set_cookie(
            key="refresh_token",
            value=refresh_token,
            max_age=config.authentication.refresh_token_validity_days * 24 * 60 * 60,
            secure=True,
            httponly=True,
            samesite="lax",
            path=f"{config.api.root_path}/refresh",
        )
        return response
    except (InvalidCredentialsError, UserNotActiveError) as exc:
        message = "Invalid credentials provided"
        logger.exception(message)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=message) from exc
    except (UserConfigFileNotFoundError, LDAPServerError) as exc:
        message = "Something went wrong"
        logger.exception(message)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=message) from exc
