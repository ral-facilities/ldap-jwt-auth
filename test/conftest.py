"""
Module for providing pytest testing configuration.
"""

from pathlib import Path

import ldap_jwt_auth.core.config as conf
from ldap_jwt_auth.core.config import Config


def pytest_configure() -> None:
    """
    This pytest hook is called for configuration of the pytest environment. It sets the `config` attribute in the
    `ldap_jwt_auth.core.config` module to an instance of a `Config` object loaded with values from the `.env.test` file.
    """
    conf.config = Config(_env_file=Path(__file__).parent / ".env.test")
