"""
Module for handling maintenance requests
"""

from ldap_jwt_auth.core.schemas import MaintenanceState


class Maintenance:
    """
    Class for managing maintenance requests.
    """

    def get_maintenance(self) -> MaintenanceState:
        """
        Return a schema reflecting the state of ims
        """
        with open('ldap_jwt_auth/maintenanceState.txt', 'r') as file:
            lines = file.readlines()
            show: bool = lines[1].strip().lower() == 'true'
            message: str = lines[3].strip()
        maintenance: MaintenanceState = MaintenanceState(show=show, message=message)
        return maintenance
