"""
Model for defining the API schema models.
"""

from pydantic import BaseModel, Field


class UserCredentials(BaseModel):
    """
    Model for the user credentials.
    """

    username: str = Field(min_length=1)
    password: str = Field(min_length=1)
