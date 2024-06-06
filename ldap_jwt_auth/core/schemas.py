"""
Model for defining the API schema models.
"""

from pydantic import BaseModel, SecretStr


class UserCredentialsPostRequestSchema(BaseModel):
    """
    Model for the user credentials.
    """

    username: SecretStr
    password: SecretStr
