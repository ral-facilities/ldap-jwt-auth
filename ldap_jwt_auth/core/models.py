"""
Model for defining the API schema models.
"""

from pydantic import BaseModel


class UserCredentials(BaseModel):
    """
    Model for the user credentials.
    """

    username: str
    password: str
