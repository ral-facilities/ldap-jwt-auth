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


class LDAPServerConfig(BaseModel):
    """
    Configuration model for the LDAP server.
    """

    url: str
    realm: str


class Config(BaseSettings):
    """
    Overall configuration model for the application.

    It includes attributes for the API, authentication, and LDAP server configurations. The class inherits from
    `BaseSettings` and automatically reads environment variables. If values are not passed in form of system environment
    variables at runtime, it will attempt to read them from the .env file.
    """

    api: APIConfig
    authentication: AuthenticationConfig
    ldap_server: LDAPServerConfig


config = Config()
