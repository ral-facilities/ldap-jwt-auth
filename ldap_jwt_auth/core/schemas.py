"""
Model for defining the API schema models.
"""

from typing import Optional
from pydantic import BaseModel, ConfigDict, SecretStr


class UserCredentialsPostRequestSchema(BaseModel):
    """
    Model for the user credentials.
    """

    username: SecretStr
    password: SecretStr

    model_config = ConfigDict(hide_input_in_errors=True)

class MaintenanceState(BaseModel):
    """
    Model for maintenancce response
    """

    show: bool
    message: str

class ScheduledMaintenanceState(MaintenanceState):
    """
    Model for scheduled maintenance state
    """
    severity: Optional[str]