"""
Module for custom exception classes.
"""


class UserConfigFileNotFoundError(Exception):
    """
    Exception raised when the file containing the user configuration cannot be found.
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


class UsernameMismatchError(Exception):
    """
    Exception raised when the usernames in the access and refresh tokens do not match.
    """


class InvalidMaintenanceFileError(Exception):
    """
    Exception raised when the maintenance state files do not have the correct format or value types.
    """


class MaintenanceFileReadError(Exception):
    """
    Exception raised when the maintenance state file's data cannot be read.
    """
