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


class AuthenticationConfig(BaseModel):
    """
    Configuration model for the authentication.
    """

    private_key_path: str
    public_key_path: str
    jwt_algorithm: str
    access_token_validity_minutes: int
    refresh_token_validity_days: int


class Config(BaseSettings):

    api: APIConfig
    authentication: AuthenticationConfig


config = Config()
