"""
Unit tests for the `JWTHandler` class.
"""
from datetime import datetime, timezone
from unittest.mock import patch

import pytest

from ldap_jwt_auth.auth.jwt_handler import JWTHandler
from ldap_jwt_auth.core.exceptions import InvalidJWTError, JWTRefreshError

VALID_ACCESS_TOKEN = (
    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InVzZXJuYW1lIiwiZXhwIjoyNTM0MDIzMDA3OTl9.bagU2Wix8wKzydVU_L3Z"
    "ZuuMAxGxV4OTuZq_kS2Fuwm839_8UZOkICnPTkkpvsm1je0AWJaIXLGgwEa5zUjpG6lTrMMmzR9Zi63F0NXpJqQqoOZpTBMYBaggsXqFkdsv-yAKUZ"
    "8MfjCEyk3UZ4PXZmEcUZcLhKcXZr4kYJPjio2e5WOGpdjK6q7s-iHGs9DQFT_IoCnw9CkyOKwYdgpB35hIGHkNjiwVSHpyKbFQvzJmIv5XCTSRYqq0"
    "1fldh-QYuZqZeuaFidKbLRH610o2-1IfPMUr-yPtj5PZ-AaX-XTLkuMqdVMCk0_jeW9Os2BPtyUDkpcu1fvW3_S6_dK3nQ"
)

VALID_REFRESH_TOKEN = (
    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjI1MzQwMjMwMDc5OX0.h4Hv_sq4-ika1rpuRx7k3pp0cF_BZ65WVSbIHS7oh9SjPpGHt"
    "GhVHU1IJXzFtyA9TH-68JpAZ24Dm6bXbH6VJKoc7RCbmJXm44ufN32ga7jDqXH340oKvi_wdhEHaCf2HXjzsHHD7_D6XIcxU71v2W5_j8Vuwpr3SdX"
    "6ea_yLIaCDWynN6FomPtUepQAOg3c7DdKohbJD8WhKIDV8UKuLtFdRBfN4HEK5nNs0JroROPhcYM9L_JIQZpdI0c83fDFuXQC-cAygzrSnGJ6O4DyS"
    "cNL3VBNSmNTBtqYOs1szvkpvF9rICPgbEEJnbS6g5kmGld3eioeuDJIxeQglSbxog"
)

EXPIRED_ACCESS_TOKEN = (
    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InVzZXJuYW1lIiwiZXhwIjotNjIxMzU1OTY4MDB9.G_cfC8PNYE5yERyyQNRk"
    "9mTmDusU_rEPgm7feo2lWQF6QMNnf8PUN-61FfMNRVE0QDSvAmIMMNEOa8ma0JHZARafgnYJfn1_FSJSoRxC740GpG8EFSWrpM-dQXnoD263V9FlK-"
    "On6IbhF-4Rh9MdoxNyZk2Lj7NvCzJ7gbgbgYM5-sJXLxB-I5LfMfuYM3fx2cRixZFA153l46tFzcMVBrAiBxl_LdyxTIOPfHF0UGlaW2UtFi02gyBU"
    "4E4wTOqPc4t_CSi1oBSbY7h9O63i8IU99YsOCdvZ7AD3ePxyM1xJR7CFHycg9Z_IDouYnJmXpTpbFMMl7SjME3cVMfMrAQ"
)

EXPIRED_REFRESH_TOKEN = (
    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOi02MjEzNTU5NjgwMH0.Er0A8dvdZi7o1FK3b-Te2IkUjDJZjI0aANsP7bbAbeITPRnR0"
    "YEhavmuLT1zaoALQjUzfSgtH0s3I-YbUr2ssqG1DnKh83uts3J2_EXIXQZBeuZisCW1nN1LC2nsR6o4HQEsbMsINjJviHeMWS8nRC06XXpN1WFPaGB"
    "xXkLFeDWb3SXiirZ79m7lUBwQvVzpfeA337e_AejG45mtadgfW3xpDCw-6sVVIA-cuzruxnjRKAzJrw_goA9X4MukRXbnzou2mgkxFKs_-6hdTFDI-"
    "B47wYqalP6KC5nqzjrCpvjmukgM-DN0uAhm2TUzUmE5EXtRLEYMRqsSmog4hYq1Nw"
)

EXPECTED_ACCESS_TOKEN = (
    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InVzZXJuYW1lIiwiZXhwIjoxNzA1NDg1OTAwfQ.aWJ8T8RGHF93YhRSP9nOAD"
    "EKY9nFjVIDu7RQhPGiMpvhgdpPBP17VQPbJ6Smt8mG1TjLXjquJZaDQRF7syrJd8ESDo-lh3ef-cMWg2hWZpbtpQaPaNHLAAMrjZo97qLxrBjeOKjY"
    "ggqwKMr-7g_LlB--z9GiQrLJVhpGxAXjnTy9VSrioZIU7OE9L9tUyOI7LGjY0X2znWQ3Loy5sMwCP_SeFHBPolKXiErKeLItriaxYNEc5l5VXD2wsK"
    "G9L8dDZZwe4BSU2eyT_2hhPTrVNfI8-J1KtwpLywC0NfS0Vaksy4HG2IbH8hpl6gaLZhtr2C5_0H_IpkTsvm_Zsnzhbg"
)

EXPECTED_REFRESH_TOKEN = (
    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MDYwOTA0MDB9.IHua0NcHiLOz7vamvcR4lxt-t51_UgzIQzho5vYK2UdHjG-bA5Sk"
    "9YhHQy480UK4FiIKohpb8G70OwmsSCjzxvbo41MZKdz3z0z_4-L0_LSGLGGmxbvPaHy6_SI8qI1f7KOAD6T3OU1zIFTcyoREEN2uNRyjMnGcQzh72d"
    "NkRAFEF3um4S2WVL0mwQ6ZltAjCiA2R8o5Eu3Aq67lkbq00ml69rfecT1JXiAfjrnW0J64COJDbQ9kVCNM1YrpqLBmROHMOOw9o7Qz1h78LbtKarVk"
    "VGaPIxhdZsWKjZwDD-6h15NZuKTAmcPUaucx6Dd4uCjJHld1BNsfKfX_81G03g"
)


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
    datetime_mock.now.return_value = mock_datetime_now()

    jwt_handler = JWTHandler()
    access_token = jwt_handler.get_access_token("username")

    assert access_token == EXPECTED_ACCESS_TOKEN


@patch("ldap_jwt_auth.auth.jwt_handler.datetime")
def test_get_refresh_token(datetime_mock):
    """
    Test getting a refresh token.
    """
    datetime_mock.now.return_value = mock_datetime_now()

    jwt_handler = JWTHandler()
    refresh_token = jwt_handler.get_refresh_token()

    assert refresh_token == EXPECTED_REFRESH_TOKEN


@patch("ldap_jwt_auth.auth.jwt_handler.datetime")
def test_refresh_access_token(datetime_mock):
    """
    Test refreshing an expired access token with a valid refresh token.
    """
    datetime_mock.now.return_value = mock_datetime_now()

    jwt_handler = JWTHandler()
    access_token = jwt_handler.refresh_access_token(EXPIRED_ACCESS_TOKEN, VALID_REFRESH_TOKEN)

    assert access_token == EXPECTED_ACCESS_TOKEN


@patch("ldap_jwt_auth.auth.jwt_handler.datetime")
def test_refresh_access_token_with_valid_access_token(datetime_mock):
    """
    Test refreshing a valid access token with a valid refresh token.
    """
    datetime_mock.now.return_value = mock_datetime_now()

    jwt_handler = JWTHandler()
    access_token = jwt_handler.refresh_access_token(VALID_ACCESS_TOKEN, VALID_REFRESH_TOKEN)

    assert access_token == EXPECTED_ACCESS_TOKEN


def test_refresh_access_token_with_invalid_access_token():
    """
    Test refreshing an invalid access token with a valid refresh token.
    """
    jwt_handler = JWTHandler()

    with pytest.raises(JWTRefreshError) as exc:
        jwt_handler.refresh_access_token("invalid", VALID_REFRESH_TOKEN)
    assert str(exc.value) == "Unable to refresh access token"


def test_refresh_access_token_with_expired_refresh_token():
    """
    Test refreshing an expired access token with an expired refresh token.
    """
    jwt_handler = JWTHandler()

    with pytest.raises(InvalidJWTError) as exc:
        jwt_handler.refresh_access_token(EXPIRED_ACCESS_TOKEN, EXPIRED_REFRESH_TOKEN)
    assert str(exc.value) == "Invalid JWT token"


def test_verify_token_with_access_token():
    """
    Test verifying a valid access token.
    """
    jwt_handler = JWTHandler()
    payload = jwt_handler.verify_token(VALID_ACCESS_TOKEN)

    assert payload == {"username": "username", "exp": 253402300799}


def test_verify_token_with_refresh_token():
    """
    Test verifying a valid refresh token.
    """
    jwt_handler = JWTHandler()
    payload = jwt_handler.verify_token(VALID_REFRESH_TOKEN)

    assert payload == {"exp": 253402300799}


def test_verify_token_with_expired_access_token():
    """
    Test verifying an expired access token.
    """
    jwt_handler = JWTHandler()

    with pytest.raises(InvalidJWTError) as exc:
        jwt_handler.verify_token(EXPIRED_ACCESS_TOKEN)
    assert str(exc.value) == "Invalid JWT token"


def test_verify_token_with_expired_refresh_token():
    """
    Test verifying an expired refresh token.
    """
    jwt_handler = JWTHandler()

    with pytest.raises(InvalidJWTError) as exc:
        jwt_handler.verify_token(EXPIRED_REFRESH_TOKEN)
    assert str(exc.value) == "Invalid JWT token"


def test_verify_token_with_invalid_token():
    """
    Test verifying an invalid access token.
    """
    jwt_handler = JWTHandler()

    with pytest.raises(InvalidJWTError) as exc:
        jwt_handler.verify_token("invalid")
    assert str(exc.value) == "Invalid JWT token"
