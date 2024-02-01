"""
Module for custom exception classes.
"""


class ActiveUsernamesFileNotFoundError(Exception):
    """
    Exception raised when the file containing the active usernames cannot be found.
    """


class InvalidCredentialsError(Exception):
    """
    Exception raised when invalid credentials are provided.
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


class UserNotActiveError(Exception):
    """
    Exception raised when user is not active.
    """
