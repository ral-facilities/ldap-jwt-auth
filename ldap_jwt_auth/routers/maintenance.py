"""
Module for providing an API router which defines maintenance route(s)
"""

import logging
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status

from ldap_jwt_auth.core.exceptions import InvalidMaintenanceFileError, MaintenanceFileReadError
from ldap_jwt_auth.core.maintenance import Maintenance
from ldap_jwt_auth.core.schemas import MaintenanceState, ScheduledMaintenanceState

logger = logging.getLogger()

router = APIRouter(tags=["maintenance"])


@router.get(
    path="/maintenance", summary="Get the maintenance state", response_description="Returns the maintenance state"
)
def get_maintenance_state(maintenance: Annotated[Maintenance, Depends(Maintenance)]) -> MaintenanceState:
    # pylint: disable=missing-function-docstring
    logger.info("Getting maintenance state")

    try:
        return maintenance.get_maintenance_state()
    except (InvalidMaintenanceFileError, MaintenanceFileReadError) as exc:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Something went wrong") from exc


@router.get(
    path="/scheduled_maintenance",
    summary="Get the scheduled maintenance state",
    response_description="Returns the scheduled maintenance state",
)
def get_scheduled_maintenance_state(
    maintenance: Annotated[Maintenance, Depends(Maintenance)],
) -> ScheduledMaintenanceState:
    # pylint: disable=missing-function-docstring
    logger.info("Getting scheduled maintenance state")
    try:
        return maintenance.get_scheduled_maintenance_state()
    except (InvalidMaintenanceFileError, MaintenanceFileReadError) as exc:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Something went wrong") from exc
