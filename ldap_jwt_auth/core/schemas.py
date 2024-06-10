"""
Model for defining the API schema models.
"""

from pydantic import BaseModel, ConfigDict, SecretStr


class UserCredentialsPostRequestSchema(BaseModel):
    """
    Model for the user credentials.
    """

    username: SecretStr
    password: SecretStr

    model_config = ConfigDict(hide_input_in_errors=True)
