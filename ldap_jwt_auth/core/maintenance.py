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
        """
        try:
            with open('ldap_jwt_auth/maintenance/maintenance.json', 'r') as file:
                data = json.load(file)
                show: bool = data.get('show')
                message: str = data.get('message')
            maintenance: MaintenanceState = MaintenanceState(show=show, message=message)
            return maintenance
        except:
            raise InvalidFileFormat

    
    def get_scheduled_maintenance(self) -> ScheduledMaintenanceState:
        """
        Return a schema for scheduled maintenance state
        """
        try:
            with open('ldap_jwt_auth/maintenance/scheduled_maintenance.json', 'r') as file:
                data = json.load(file)
                show: bool = data.get('show')
                message: str = data.get('message')
                severity: Optional[str] = data.get('severity')
            maintenance: MaintenanceState = ScheduledMaintenanceState(show=show, message=message, severity=severity)
            return maintenance
        except:
            raise InvalidFileFormat
