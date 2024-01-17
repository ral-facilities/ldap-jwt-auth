"""
Unit tests for the `JWTHandler` class.
"""
from datetime import datetime, timezone
from unittest.mock import patch

from ldap_jwt_auth.auth.jwt_handler import JWTHandler


def mock_datetime_now() -> datetime:
    """
    Mock function to return a predefined datetime object.
    :return: Predefined datetime object.
    """
    return datetime(2024, 1, 17, 10, 0, 0, 0, tzinfo=timezone.utc)


@patch("ldap_jwt_auth.auth.jwt_handler.datetime")
def test_get_access_token(datetime_mock):
    """
    Test getting an access token.
    """
    expected_access_token = (
        "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InVzZXJuYW1lIiwiZXhwIjoxNzA1NDg1OTAwfQ.aWJ8T8RGHF93YhRSP9"
        "nOADEKY9nFjVIDu7RQhPGiMpvhgdpPBP17VQPbJ6Smt8mG1TjLXjquJZaDQRF7syrJd8ESDo-lh3ef-cMWg2hWZpbtpQaPaNHLAAMrjZo97qLx"
        "rBjeOKjYggqwKMr-7g_LlB--z9GiQrLJVhpGxAXjnTy9VSrioZIU7OE9L9tUyOI7LGjY0X2znWQ3Loy5sMwCP_SeFHBPolKXiErKeLItriaxYN"
        "Ec5l5VXD2wsKG9L8dDZZwe4BSU2eyT_2hhPTrVNfI8-J1KtwpLywC0NfS0Vaksy4HG2IbH8hpl6gaLZhtr2C5_0H_IpkTsvm_Zsnzhbg"
    )
    datetime_mock.now.return_value = mock_datetime_now()

    jwt_handler = JWTHandler()
    access_token = jwt_handler.get_access_token("username")

    assert access_token == expected_access_token


@patch("ldap_jwt_auth.auth.jwt_handler.datetime")
def test_get_refresh_token(datetime_mock):
    """
    Test getting a refresh token.
    """
    expected_refresh_token = (
        "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MDYwOTA0MDB9.IHua0NcHiLOz7vamvcR4lxt-t51_UgzIQzho5vYK2UdHjG-b"
        "A5Sk9YhHQy480UK4FiIKohpb8G70OwmsSCjzxvbo41MZKdz3z0z_4-L0_LSGLGGmxbvPaHy6_SI8qI1f7KOAD6T3OU1zIFTcyoREEN2uNRyjMn"
        "GcQzh72dNkRAFEF3um4S2WVL0mwQ6ZltAjCiA2R8o5Eu3Aq67lkbq00ml69rfecT1JXiAfjrnW0J64COJDbQ9kVCNM1YrpqLBmROHMOOw9o7Qz"
        "1h78LbtKarVkVGaPIxhdZsWKjZwDD-6h15NZuKTAmcPUaucx6Dd4uCjJHld1BNsfKfX_81G03g"
    )
    datetime_mock.now.return_value = mock_datetime_now()

    jwt_handler = JWTHandler()
    refresh_token = jwt_handler.get_refresh_token()

    assert refresh_token == expected_refresh_token
