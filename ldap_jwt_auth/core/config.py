"""
Module for the overall configuration for the application.
"""

from typing import List, Optional

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator
from pydantic_core.core_schema import ValidationInfo
from pydantic_settings import BaseSettings, SettingsConfigDict


class APIConfig(BaseModel):
    """
    Configuration model for the API.
    """

    title: str = "LDAP-JWT Authentication Service API"
    description: str = "This is the API for the LDAP-JWT Authentication Service"
    root_path: str = ""  # (If using a proxy) The path prefix handled by a proxy that is not seen by the app.
    allowed_cors_headers: List[str]
    allowed_cors_origins: List[str]
    allowed_cors_methods: List[str]


class MaintenanceConfig(BaseModel):
    """
    Configuration model for maintenance
    """

    maintenance_path: str
    scheduled_maintenance_path: str


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

    url: SecretStr
    realm: SecretStr
    certificate_validation: bool
    ca_certificate_file_path: Optional[str] = Field(default=None, validate_default=True)

    model_config = ConfigDict(hide_input_in_errors=True)

    @field_validator("ca_certificate_file_path")
    @classmethod
    def validate_optional_fields(cls, field_value: str, info: ValidationInfo) -> Optional[str]:
        """
        Validator for the `ca_certificate_file_path` field to make it mandatory if the value of the
        `certificate_validation` field is `True`

        It checks if the `certificate_validation` field has been set to `True` and raises a `TypeError` if this is the
        case.

        :param field_value: The value of the field.
        :param info: Validation info from pydantic.
        :raises ValueError: If no value is provided for the field when `certificate_validation` is set to `True`.
        :return: The value of the field.
        """
        if (
            "certificate_validation" in info.data and info.data["certificate_validation"] is True
        ) and field_value is None:
            raise ValueError("Field required")
        return field_value


class OIDCProviderConfig(BaseModel):
    """
    Configuration model for an OIDC provider.
    """

    display_name: str
    configuration_url: str
    client_id: str
    verify_cert: bool = True
    request_timeout_seconds: int = 10
    scope: str = "openid"
    username_claim: str = "email"


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
    maintenance: MaintenanceConfig
    oidc_providers: dict[str, OIDCProviderConfig] = {}

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_nested_delimiter="__",
        hide_input_in_errors=True,
    )


config = Config()
