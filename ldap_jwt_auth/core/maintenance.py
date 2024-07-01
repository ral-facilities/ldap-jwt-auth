"""
Module for handling maintenance mode
"""

import json
import logging

from pydantic import ValidationError
from ldap_jwt_auth.core.config import config
from ldap_jwt_auth.core.exceptions import InvalidMaintenanceFileError, MaintenanceFileReadError
from ldap_jwt_auth.core.schemas import MaintenanceState, ScheduledMaintenanceState

logger = logging.getLogger()


class Maintenance:
    """
    Class for managing maintenance and scheduled maintenance states.
    """

    def get_maintenance_state(self) -> MaintenanceState:
        """
        Return the maintenance state of the system

        :return: Maintenance state
        :raises InvalidFileFormat: If the maintenance state file is incorrectly formatted
        :raises MaintenanceFileReadError: If the scheduled maintenance state file's data cannot be read
        """
        try:
            with open(config.maintenance.maintenance_path, "r", encoding="utf-8") as file:
                data = json.load(file)
            return MaintenanceState(**data)
        except (OSError, json.JSONDecodeError, TypeError) as exc:
            message = "An error occurred while trying to find and read the maintenance file"
            logger.exception(message)
            raise MaintenanceFileReadError(message) from exc
        except ValidationError as exc:
            message = "An error occurred while validating the data in the maintenance file"
            logger.exception(message)
            raise InvalidMaintenanceFileError(message) from exc

    def get_scheduled_maintenance_state(self) -> ScheduledMaintenanceState:
        """
        Return the scheduled maintenance state of the system

        :return: Scheduled maintenance state
        :raises InvalidFileFormat: If the scheduled maintenance state file is incorrectly formatted
        :raises MaintenanceFileReadError: If the scheduled maintenance state file's data cannot be read
        """
        try:
            with open(config.maintenance.scheduled_maintenance_path, "r", encoding="utf-8") as file:
                data = json.load(file)
            return ScheduledMaintenanceState(**data)
        except (OSError, json.JSONDecodeError, TypeError) as exc:
            message = "An error occurred while trying to find and read the scheduled maintenance file"
            logger.exception(message)
            raise MaintenanceFileReadError(message) from exc
        except ValidationError as exc:
            message = "An error occurred while validating the data in the scheduled maintenance file"
            logger.exception(message)
            raise InvalidMaintenanceFileError(message) from exc
