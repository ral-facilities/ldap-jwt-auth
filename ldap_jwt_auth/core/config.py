"""
Module for the overall configuration for the application.
"""
from pydantic import BaseModel
from pydantic_settings import BaseSettings


class APIConfig(BaseModel):
    """
    Configuration model for the API.
    """

    title: str = "LDAP-JWT Authentication Service API"
    description: str = "This is the API for the LDAP-JWT Authentication Service"
    root_path: str = ""  # (If using a proxy) The path prefix handled by a proxy that is not seen by the app.


class Config(BaseSettings):

    api: APIConfig


config = Config()
