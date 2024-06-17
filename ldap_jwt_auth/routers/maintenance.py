"""
Module for providing an API router which defines maintenance route(s)
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
from ldap_jwt_auth.core.maintenance import Maintenance
from ldap_jwt_auth.core.schemas import MaintenanceState, UserCredentialsPostRequestSchema

logger = logging.getLogger()

router = APIRouter(prefix="/maintenance", tags=["maintenance"])

@router.get(
    path="",
    summary="Get the maintenance state",
    response_description="Returns the maintenance state"
)
def get_maintenance_state(
    maintenance: Annotated[Maintenance, Depends(Maintenance)]
) -> MaintenanceState:
    logger.info('Getting maintenance state')
    return maintenance.get_maintenance()