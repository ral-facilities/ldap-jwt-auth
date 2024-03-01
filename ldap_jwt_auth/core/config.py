"""
Module for the overall configuration for the application.
"""

from pathlib import Path
from typing import List

from pydantic import BaseModel
from pydantic_settings import SettingsConfigDict, BaseSettings


class APIConfig(BaseModel):
    """
    Configuration model for the API.
    """

    title: str = "LDAP-JWT Authentication Service API"
    description: str = "This is the API for the LDAP-JWT Authentication Service"
    root_path: str = ""  # (If using a proxy) The path prefix handled by a proxy that is not seen by the app.
    allowed_cors_headers: List[str]
    allowed_cors_origins: List[str]


class AuthenticationConfig(BaseModel):
    """
    Configuration model for the authentication.
    """

    private_key_path: str
    public_key_path: str
    jwt_algorithm: str
    access_token_validity_minutes: int
    refresh_token_validity_days: int
    active_usernames_path: str


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

    model_config = SettingsConfigDict(
        env_file=Path(__file__).parent.parent / ".env", env_file_encoding="utf-8", env_nested_delimiter="__"
    )


config = Config()
