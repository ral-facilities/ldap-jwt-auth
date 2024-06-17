"""
Module for handling maintenance requests
"""

from typing import Optional
from ldap_jwt_auth.core.schemas import MaintenanceState, ScheduledMaintenanceState


class Maintenance:
    """
    Class for managing maintenance requests.
    """

    def get_maintenance(self) -> MaintenanceState:
        """
        Return a schema for maintenance state of ims
        """
        with open('ldap_jwt_auth/maintenanceState.txt', 'r') as file:
            lines = file.readlines()
            show: bool = lines[1].strip().lower() == 'true'
            message: str = lines[3].strip()
        maintenance: MaintenanceState = MaintenanceState(show=show, message=message)
        return maintenance
    
    def get_scheduled_maintenance(self) -> ScheduledMaintenanceState:
        """
        Return a schema for scheduled maintenance state
        """
        with open('ldap_jwt_auth/maintenanceState.txt', 'r') as file:
            lines = file.readlines()
            show: bool = lines[1].strip().lower() == 'true'
            message: str = lines[3].strip()
            severity: Optional[str] = lines[5].strip()
        maintenance: MaintenanceState = ScheduledMaintenanceState(show=show, message=message, severity=severity)
        return maintenance
