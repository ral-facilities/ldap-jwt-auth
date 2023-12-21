"""
Module for providing an API router which defines a route for managing the refreshing/updating of a JWT access token
using a JWT refresh token.
"""
import logging
from typing import Annotated

from fastapi import APIRouter, Cookie, Depends, HTTPException, Query, status
from fastapi.responses import JSONResponse

from ldap_jwt_auth.auth.jwt_hanlder import JWTHandler
from ldap_jwt_auth.core.exceptions import JWTRefreshError

logger = logging.getLogger()

router = APIRouter(prefix="/refresh", tags=["authentication"])


@router.post(
    path="/",
    summary="Generate an updated JWT access token using the JWT refresh token",
    response_description="A JWT access token",
)
def refresh_access_token(
    jwt_handler: Annotated[JWTHandler, Depends(JWTHandler)],
    access_token: Annotated[str, Query(description="The JWT access token to refresh")],
    refresh_token: Annotated[str | None, Cookie(description="The JWT refresh token from an HTTP-only cookie")] = None,
) -> JSONResponse:
    # pylint: disable=missing-function-docstring
    if refresh_token is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No JWT refresh token found")

    try:
        access_token = jwt_handler.refresh_access_token(access_token, refresh_token)
        return JSONResponse(content=access_token)
    except JWTRefreshError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
