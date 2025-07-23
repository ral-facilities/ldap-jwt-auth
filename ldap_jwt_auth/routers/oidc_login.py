"""
Module for providing an API router which defines login route(s).
"""

import logging
from typing import Annotated

from fastapi import APIRouter, Body, Depends, HTTPException, status
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from ldap_jwt_auth.auth.jwt_handler import JWTHandler
from ldap_jwt_auth.auth.oidc_handler import OidcHandler
from ldap_jwt_auth.core.config import config
from ldap_jwt_auth.core.exceptions import UserNotActiveError, OIDCServerError, ActiveUserEmailsFileNotFoundError

logger = logging.getLogger()

router = APIRouter(tags=["authentication"])


@router.post(
    path="/oidc_login",
    summary="Login with an OIDC ID token",
    response_description="A JWT access token including a refresh token as an HTTP-only cookie",
)
def login(
    oidc_handler: Annotated[OidcHandler, Depends(OidcHandler)],
    jwt_handler: Annotated[JWTHandler, Depends(JWTHandler)],
    bearer_token: Annotated[HTTPAuthorizationCredentials, Depends(HTTPBearer(description="OIDC ID token"))]
) -> JSONResponse:
    # pylint: disable=missing-function-docstring

    encoded_token = bearer_token.credentials
    try:
        oidc_username = oidc_handler.handle(encoded_token)
        access_token = jwt_handler.get_access_token(oidc_username)
        refresh_token = jwt_handler.get_refresh_token(oidc_username)

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
    except UserNotActiveError as exc:
        message = "Invalid credentials provided"
        logger.exception(message)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=message) from exc
    except OIDCServerError as exc:
        message = "Something went wrong"
        logger.exception(message)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=message) from exc
    except ActiveUserEmailsFileNotFoundError as exc:
        message = "Something went wrong"
        logger.exception(message)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=message) from exc
