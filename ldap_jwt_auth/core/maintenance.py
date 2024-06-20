"""
Module for handling maintenance requests
"""

import json

from pydantic import ValidationError
from ldap_jwt_auth.core.exceptions import InvalidMaintenanceFileFormat, MissingMaintenanceFile
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
            with open("maintenance/maintenance.json", "r", encoding='utf-8') as file:
                data = json.load(file)
            maintenance: MaintenanceState = MaintenanceState(**data)
            return maintenance
        except IOError as exc:
            print(exc)
            raise MissingMaintenanceFile("Unable to find maintenance file") from exc
        except ValidationError as exc:
            raise InvalidMaintenanceFileFormat("Maintenance file format is incorrect") from exc

    def get_scheduled_maintenance(self) -> ScheduledMaintenanceState:
        """
        Return a schema for scheduled maintenance state

        :return: Scheduled maintenance state schema
        :raises InvalidFileFormat: If the scheduled maintenance state file is incorrectly formatted
        """
        try:
            with open("maintenance/scheduled_maintenance.json", "r", encoding='utf-8') as file:
                data = json.load(file)
            maintenance: MaintenanceState = ScheduledMaintenanceState(**data)
            return maintenance
        except IOError as exc:
            raise MissingMaintenanceFile("Unable to find scheduled maintenance file") from exc
        except ValidationError as exc:
            raise InvalidMaintenanceFileFormat("Scheduled maintenance file format is incorrect") from exc
