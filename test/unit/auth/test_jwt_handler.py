"""
Unit tests for the `JWTHandler` class.
"""
from datetime import datetime, timezone
from unittest.mock import patch

import pytest

from ldap_jwt_auth.auth.jwt_handler import JWTHandler
from ldap_jwt_auth.core.exceptions import InvalidJWTError


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


def test_verify_token_with_access_token():
    """
    Test verifying a valid access token.
    """
    access_token = (
        "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InVzZXJuYW1lIiwiZXhwIjoyNTM0MDIzMDA3OTl9.bagU2Wix8wKzydVU"
        "_L3ZZuuMAxGxV4OTuZq_kS2Fuwm839_8UZOkICnPTkkpvsm1je0AWJaIXLGgwEa5zUjpG6lTrMMmzR9Zi63F0NXpJqQqoOZpTBMYBaggsXqFkd"
        "sv-yAKUZ8MfjCEyk3UZ4PXZmEcUZcLhKcXZr4kYJPjio2e5WOGpdjK6q7s-iHGs9DQFT_IoCnw9CkyOKwYdgpB35hIGHkNjiwVSHpyKbFQvzJm"
        "Iv5XCTSRYqq01fldh-QYuZqZeuaFidKbLRH610o2-1IfPMUr-yPtj5PZ-AaX-XTLkuMqdVMCk0_jeW9Os2BPtyUDkpcu1fvW3_S6_dK3nQ"
    )

    jwt_handler = JWTHandler()
    payload = jwt_handler.verify_token(access_token)

    assert payload == {"username": "username", "exp": 253402300799}


def test_verify_token_with_refresh_token():
    """
    Test verifying a valid refresh token.
    """
    refresh_token = (
        "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjI1MzQwMjMwMDc5OX0.h4Hv_sq4-ika1rpuRx7k3pp0cF_BZ65WVSbIHS7oh9SjP"
        "pGHtGhVHU1IJXzFtyA9TH-68JpAZ24Dm6bXbH6VJKoc7RCbmJXm44ufN32ga7jDqXH340oKvi_wdhEHaCf2HXjzsHHD7_D6XIcxU71v2W5_j8V"
        "uwpr3SdX6ea_yLIaCDWynN6FomPtUepQAOg3c7DdKohbJD8WhKIDV8UKuLtFdRBfN4HEK5nNs0JroROPhcYM9L_JIQZpdI0c83fDFuXQC-cAyg"
        "zrSnGJ6O4DyScNL3VBNSmNTBtqYOs1szvkpvF9rICPgbEEJnbS6g5kmGld3eioeuDJIxeQglSbxog"
    )

    jwt_handler = JWTHandler()
    payload = jwt_handler.verify_token(refresh_token)

    assert payload == {"exp": 253402300799}


def test_verify_token_with_expired_access_token():
    """
    Test verifying an expired access token.
    """
    expired_access_token = (
        "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InVzZXJuYW1lIiwiZXhwIjotNjIxMzU1OTY4MDB9.G_cfC8PNYE5yERyy"
        "QNRk9mTmDusU_rEPgm7feo2lWQF6QMNnf8PUN-61FfMNRVE0QDSvAmIMMNEOa8ma0JHZARafgnYJfn1_FSJSoRxC740GpG8EFSWrpM-dQXnoD2"
        "63V9FlK-On6IbhF-4Rh9MdoxNyZk2Lj7NvCzJ7gbgbgYM5-sJXLxB-I5LfMfuYM3fx2cRixZFA153l46tFzcMVBrAiBxl_LdyxTIOPfHF0UGla"
        "W2UtFi02gyBU4E4wTOqPc4t_CSi1oBSbY7h9O63i8IU99YsOCdvZ7AD3ePxyM1xJR7CFHycg9Z_IDouYnJmXpTpbFMMl7SjME3cVMfMrAQ"
    )

    jwt_handler = JWTHandler()

    with pytest.raises(InvalidJWTError) as exc:
        jwt_handler.verify_token(expired_access_token)
    assert str(exc.value) == "Invalid JWT token"


def test_verify_token_with_expired_refresh_token():
    """
    Test verifying an expired refresh token.
    """
    expired_refresh_tokenb = (
        "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOi02MjEzNTU5NjgwMH0.Er0A8dvdZi7o1FK3b-Te2IkUjDJZjI0aANsP7bbAbeITP"
        "RnR0YEhavmuLT1zaoALQjUzfSgtH0s3I-YbUr2ssqG1DnKh83uts3J2_EXIXQZBeuZisCW1nN1LC2nsR6o4HQEsbMsINjJviHeMWS8nRC06XXp"
        "N1WFPaGBxXkLFeDWb3SXiirZ79m7lUBwQvVzpfeA337e_AejG45mtadgfW3xpDCw-6sVVIA-cuzruxnjRKAzJrw_goA9X4MukRXbnzou2mgkxF"
        "Ks_-6hdTFDI-B47wYqalP6KC5nqzjrCpvjmukgM-DN0uAhm2TUzUmE5EXtRLEYMRqsSmog4hYq1Nw"
    )

    jwt_handler = JWTHandler()

    with pytest.raises(InvalidJWTError) as exc:
        jwt_handler.verify_token(expired_refresh_tokenb)
    assert str(exc.value) == "Invalid JWT token"
