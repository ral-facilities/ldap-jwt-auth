"""
Module for custom exception classes.
"""


class LDAPServerError(Exception):
    """
    Exception raised when there is problem with the LDAP server.
    """


class InvalidCredentialsError(Exception):
    """
    Exception raised when invalid credentials are provided.
    """
