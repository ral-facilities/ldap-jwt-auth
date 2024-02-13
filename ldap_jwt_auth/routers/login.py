"""
Module for providing an API router which defines login route(s).
"""

import logging
from typing import Annotated

from fastapi import APIRouter, Body, Depends, HTTPException, status
from fastapi.responses import JSONResponse

from ldap_jwt_auth.auth.authentication import Authentication
from ldap_jwt_auth.auth.jwt_handler import JWTHandler
from ldap_jwt_auth.core.config import config
from ldap_jwt_auth.core.exceptions import (
    InvalidCredentialsError,
    LDAPServerError,
    UserNotActiveError,
    ActiveUsernamesFileNotFoundError,
)
from ldap_jwt_auth.core.schemas import UserCredentialsPostRequestSchema

logger = logging.getLogger()

router = APIRouter(prefix="/login", tags=["authentication"])


@router.post(
    path="",
    summary="Login with a username and password",
    response_description="A JWT access token including a refresh token as an HTTP-only cookie",
)
def login(
    user_credentials: Annotated[UserCredentialsPostRequestSchema, Body(description="The credentials of the user")],
    authentication: Annotated[Authentication, Depends(Authentication)],
    jwt_handler: Annotated[JWTHandler, Depends(JWTHandler)],
) -> JSONResponse:
    # pylint: disable=missing-function-docstring
    try:
        authentication.authenticate(user_credentials)
        access_token = jwt_handler.get_access_token(user_credentials.username)
        refresh_token = jwt_handler.get_refresh_token()

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
    except LDAPServerError as exc:
        message = "Something went wrong"
        logger.exception(message)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=message) from exc
    except ActiveUsernamesFileNotFoundError as exc:
        message = "Something went wrong"
        logger.exception(message)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=message) from exc
