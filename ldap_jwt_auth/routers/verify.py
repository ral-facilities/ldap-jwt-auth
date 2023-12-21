"""
Module for providing an API router which defines a route for managing verification of JWT tokens.
"""
import logging
from typing import Annotated

from fastapi import APIRouter, Body, Depends, HTTPException, Response, status

from ldap_jwt_auth.auth.jwt_hanlder import JWTHandler
from ldap_jwt_auth.core.exceptions import InvalidJWTError

logger = logging.getLogger()

router = APIRouter(prefix="/verify", tags=["authentication"])


@router.post(
    path="/",
    summary="Verify that a JWT token was generated by this authentication service",
    response_description="200 status code (no response body) if the token is valid",
)
def verify_token(
    jwt_handler: Annotated[JWTHandler, Depends(JWTHandler)],
    token: Annotated[str, Body(description="The JWT token to verify")],
) -> Response:
    # pylint: disable=missing-function-docstring
    try:
        jwt_handler.verify_token(token)
        return Response(status_code=status.HTTP_200_OK)
    except InvalidJWTError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid JWT token provided") from exc
