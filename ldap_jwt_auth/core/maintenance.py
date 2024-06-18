"""
Module for handling maintenance requests
"""

import json
from typing import Optional
from ldap_jwt_auth.core.exceptions import InvalidFileFormat
from ldap_jwt_auth.core.schemas import MaintenanceState, ScheduledMaintenanceState


class Maintenance:
    """
    Class for managing maintenance requests.
    """

    def get_maintenance(self) -> MaintenanceState:
        """
        Return a schema for maintenance state of ims

        :return: Maintenance state schema
        :raises InvalidFileFormat: If the maintenance state file is incorrectly formatted
        """
        try:
            with open("ldap_jwt_auth/maintenance/maintenance.json", "r", encoding='utf-8') as file:
                data = json.load(file)
                show: bool = data.get("show")
                message: str = data.get("message")
            maintenance: MaintenanceState = MaintenanceState(show=show, message=message)
            return maintenance
        except Exception as exc:
            raise InvalidFileFormat("Maintenance file format is incorrect") from exc

    def get_scheduled_maintenance(self) -> ScheduledMaintenanceState:
        """
        Return a schema for scheduled maintenance state

        :return: Scheduled maintenance state schema
        :raises InvalidFileFormat: If the scheduled maintenance state file is incorrectly formatted
        """
        try:
            with open("ldap_jwt_auth/maintenance/scheduled_maintenance.json", "r", encoding='utf-8') as file:
                data = json.load(file)
                show: bool = data.get("show")
                message: str = data.get("message")
                severity: Optional[str] = data.get("severity")
            maintenance: MaintenanceState = ScheduledMaintenanceState(show=show, message=message, severity=severity)
            return maintenance
        except Exception as exc:
            raise InvalidFileFormat("Scheduled Maintenance file format is incorrect") from exc
