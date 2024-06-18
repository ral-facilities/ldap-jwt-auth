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
    InvalidFileFormat,
    LDAPServerError,
    UserNotActiveError,
    ActiveUsernamesFileNotFoundError,
)
from ldap_jwt_auth.core.maintenance import Maintenance
from ldap_jwt_auth.core.schemas import MaintenanceState, ScheduledMaintenanceState, UserCredentialsPostRequestSchema

logger = logging.getLogger()

router = APIRouter(tags=["maintenance"])


@router.get(
    path="/maintenance", summary="Get the maintenance state", response_description="Returns the maintenance state"
)
def get_maintenance_state(maintenance: Annotated[Maintenance, Depends(Maintenance)]) -> MaintenanceState:
    logger.info("Getting maintenance state")

    try:
        return maintenance.get_maintenance()

    except InvalidFileFormat as exc:
        message = "Maintenance file format is incorrect"
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=message)


@router.get(
    path="/scheduled_maintenance",
    summary="Get the scheduled maintenance state",
    response_description="Returns the scheduled maintenance state",
)
def get_scheduled_maintenance_state(
    maintenance: Annotated[Maintenance, Depends(Maintenance)]
) -> ScheduledMaintenanceState:
    logger.info("Getting scheduled maintenance state")
    try:
        return maintenance.get_scheduled_maintenance()

    except InvalidFileFormat as exc:
        message = "Scheduled Maintenance file format is incorrect"
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=message)
