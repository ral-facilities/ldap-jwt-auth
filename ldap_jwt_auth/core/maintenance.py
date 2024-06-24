"""
Module for handling maintenance mode
"""

import json

from pydantic import ValidationError
from ldap_jwt_auth.core.config import config
from ldap_jwt_auth.core.exceptions import InvalidMaintenanceFileError, MissingMaintenanceFileError
from ldap_jwt_auth.core.schemas import MaintenanceState, ScheduledMaintenanceState

class Maintenance:
    """
    Class for managing maintenance and scheduled maintenance states.
    """

    def get_maintenance_state(self) -> MaintenanceState:
        """
        Return the maintenance state of the system

        :return: Maintenance state schema
        :raises InvalidFileFormat: If the maintenance state file is incorrectly formatted
        :raises MissingMaintenanceFileError: If the maintenance state file can not be found or read
        """
        try:
            with open(config.maintenance.maintenance_path, "r", encoding='utf-8') as file:
                data = json.load(file)
            return MaintenanceState(**data)
        except (OSError, json.JSONDecodeError, TypeError) as exc:
            raise MissingMaintenanceFileError("Unable to find maintenance file") from exc
        except ValidationError as exc:
            raise InvalidMaintenanceFileError("Maintenance file format is incorrect") from exc

    def get_scheduled_maintenance_state(self) -> ScheduledMaintenanceState:
        """
        Return the scheduled maintenance state of the system

        :return: Scheduled maintenance state schema
        :raises InvalidFileFormat: If the scheduled maintenance state file is incorrectly formatted
        :raises MissingMaintenanceFileError: If the scheduled maintenance state file can not be found or read
        """
        try:
            with open(config.maintenance.scheduled_maintenance_path, "r", encoding='utf-8') as file:
                data = json.load(file)
            return ScheduledMaintenanceState(**data)
        except (OSError, json.JSONDecodeError, TypeError) as exc:
            raise MissingMaintenanceFileError("Unable to find scheduled maintenance file") from exc
        except ValidationError as exc:
            raise InvalidMaintenanceFileError("Scheduled maintenance file format is incorrect") from exc
