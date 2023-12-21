"""
Module for custom exception classes.
"""


class InvalidJWTError(Exception):
    """
    Exception raised when invalid JWT token is provided.
    """


class JWTRefreshError(Exception):
    """
    Exception raised when JWT access token cannot be refreshed.
    """


class LDAPServerError(Exception):
    """
    Exception raised when there is problem with the LDAP server.
    """


class InvalidCredentialsError(Exception):
    """
    Exception raised when invalid credentials are provided.
    """
