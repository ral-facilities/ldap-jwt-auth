"""
Unit tests for the `JWTHandler` class.
"""

from datetime import datetime, timezone
from unittest.mock import patch

import pytest

from ldap_jwt_auth.auth.jwt_handler import JWTHandler
from ldap_jwt_auth.core.exceptions import InvalidJWTError, JWTRefreshError, UsernameMismatchError, UserNotActiveError

VALID_ACCESS_TOKEN = (
    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InVzZXJuYW1lIiwicm9sZSI6ImFkbWluIiwidXNlcklzQWRtaW4iOmZhbHNlL"
    "CJleHAiOjI1MzQwMjMwMDc5OX0.FrsDUqnKskhIvmIjtYVgC9im-cSu1dFlwVQ4cFJf2BgCaSh82XuEngOLkbtQuuXWC1wiipsGP4Y-usq7Q_R68vw"
    "XqGYusHo4fXw6AcBcwplgXZ3n60wsTegpBxKZY5foOre0Ng1GpK-7rrx9H-YQUCHSBOtzWOw_eLzu-eNTwMnMnnpGM9L91_hj0dAKiP90Z3Hp0Ueln"
    "Yydc0sf6msOs7RKI2Sij-13vFSL8LToIbfUTZYwKZHbBPD5glce_gsW6_W5W-iGemt7yyhfyf7IxKWq3Q02HCiSkI0uCcBal44sabPrsQ4EaPRwyUn"
    "H0X25MC00IAPRHh-1KqabV7IA9w"
)

VALID_REFRESH_TOKEN = (
    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InVzZXJuYW1lIiwicm9sZSI6ImFkbWluIiwidXNlcklzQWRtaW4iOmZhbHNlL"
    "CJleHAiOjI1MzQwMjMwMDc5OX0.FrsDUqnKskhIvmIjtYVgC9im-cSu1dFlwVQ4cFJf2BgCaSh82XuEngOLkbtQuuXWC1wiipsGP4Y-usq7Q_R68vw"
    "XqGYusHo4fXw6AcBcwplgXZ3n60wsTegpBxKZY5foOre0Ng1GpK-7rrx9H-YQUCHSBOtzWOw_eLzu-eNTwMnMnnpGM9L91_hj0dAKiP90Z3Hp0Ueln"
    "Yydc0sf6msOs7RKI2Sij-13vFSL8LToIbfUTZYwKZHbBPD5glce_gsW6_W5W-iGemt7yyhfyf7IxKWq3Q02HCiSkI0uCcBal44sabPrsQ4EaPRwyUn"
    "H0X25MC00IAPRHh-1KqabV7IA9w"
)
EXPIRED_ACCESS_TOKEN = (
    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InVzZXJuYW1lIiwicm9sZSI6ImFkbWluIiwidXNlcklzQWRtaW4iOmZhbHNlL"
    "CJleHAiOjk0NjY4NDc5OX0.EQnEYrwwwjuudk_mBdAe_V4dts-nTSU2WEoxyahVfsmCWOAAsyNbRvctGPLBaXIzMU73dgtKMpIiE9etlWKhP68GWRG"
    "21x155-Qm8i_sJu4r6AOcjwPQRV1fPxf5s37L9V-nj1cWgc_HpBJWSG_DnJtZ_T4AQULYDmZRgoGmRl6UsvavKFYFMHwjSRAcSWlT2yn2YjGZ2vDhS"
    "FSEsdj77XM7JC3OiNb6nLJz4pCYlHsNDxp0XRrKrgx7sYlyDgMIJpfK9OrCsf8r02qdVct2SOYaGP7VXYs17xo5JRSGACq9UUPdbz1Vv-q-7ra2GJX"
    "Yex1UzoTFh5LzOf-UMtLSKA"
)
EXPIRED_REFRESH_TOKEN = (
    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InVzZXJuYW1lIiwicm9sZSI6ImFkbWluIiwidXNlcklzQWRtaW4iOmZhbHNlL"
    "CJleHAiOjk0NjY4NDc5OX0.EQnEYrwwwjuudk_mBdAe_V4dts-nTSU2WEoxyahVfsmCWOAAsyNbRvctGPLBaXIzMU73dgtKMpIiE9etlWKhP68GWRG"
    "21x155-Qm8i_sJu4r6AOcjwPQRV1fPxf5s37L9V-nj1cWgc_HpBJWSG_DnJtZ_T4AQULYDmZRgoGmRl6UsvavKFYFMHwjSRAcSWlT2yn2YjGZ2vDhS"
    "FSEsdj77XM7JC3OiNb6nLJz4pCYlHsNDxp0XRrKrgx7sYlyDgMIJpfK9OrCsf8r02qdVct2SOYaGP7VXYs17xo5JRSGACq9UUPdbz1Vv-q-7ra2GJX"
    "Yex1UzoTFh5LzOf-UMtLSKA"
)

EXPECTED_ACCESS_TOKEN = (
    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InVzZXJuYW1lIiwicm9sZSI6ImFkbWluIiwidXNlcklzQWRtaW4iOmZhbHNlL"
    "CJleHAiOjE3MDU0ODU5MDB9.l9-3DudRuhtyHr_dcKp6XvjMRorV9XI4l7CaSBI5CKiH2UCynHcepW0frKKgBfVyo8neEHSCQRE9TQK0c69NQuZJgo"
    "IEow3M3AOWy5MgbrYLpjCUpCC9XZgAKbj4QGuro_z5FJ-fUsZr2swGP_MLLlMAilYdTlU-7AHoL6OrmHWHsXOuCjh1V-KbSTRjQPCfkxB8tOQOglgf"
    "c5ci737AQ7HWu_K3hCcV_ozwy3uGsET3g5V-LDncosicPgZl-7a5WX2aIdPILpx3SQzzJ8_kwHrotvpd1UeSwzqIT1CBGccYkbp-aQMmWIaTN3cyjN"
    "ZYRHcMNSRUcewieSi2KUwScw"
)

EXPECTED_REFRESH_TOKEN = (
    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InVzZXJuYW1lIiwicm9sZSI6ImFkbWluIiwidXNlcklzQWRtaW4iOmZhbHNlL"
    "CJleHAiOjE3MDYwOTA0MDB9.gagdip1GIPwTDKvlTKK8J1Y36s5mFljW5iNpRdqMnF8kiNpcmFJwHwXG8hQ-PpO3h0jgyK85KLe0JQKszz91i0Nbnm"
    "bHjhWqB2e_vfqt5lAfA9POE-pvLv4BPqXNBO8sItAztgbBSziAH5ZwLHyhpExMY6I-EQi0veDWIaZQHBh4Cq2vlwnGwE8E3tQN5MzTZr0ROL9hirE0"
    "1ADEMtTpIxjQxiA6jIHXVKXu0d04r-873iXZ2eNnt-3AFseWnYdmD98JROB8b0IeyoLFfbpaLBNjRMTinvdYBoSs64PeuU90uUOoA8DmGrDYLpYiel"
    "q3W_DIDgiG64Df7e2Aj1icZg"
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
    refresh_token = jwt_handler.get_refresh_token("username")

    assert refresh_token == EXPECTED_REFRESH_TOKEN


@patch("ldap_jwt_auth.auth.jwt_handler.Authorisation.is_active_user")
@patch("ldap_jwt_auth.auth.jwt_handler.datetime")
def test_refresh_access_token(datetime_mock, is_user_active_mock):
    """
    Test refreshing an expired access token with a valid refresh token.
    """
    datetime_mock.now.return_value = mock_datetime_now()
    is_user_active_mock.return_value = True

    jwt_handler = JWTHandler()
    access_token = jwt_handler.refresh_access_token(EXPIRED_ACCESS_TOKEN, VALID_REFRESH_TOKEN)

    assert access_token == EXPECTED_ACCESS_TOKEN


@patch("ldap_jwt_auth.auth.jwt_handler.Authorisation.is_active_user")
def test_refresh_access_token_with_non_matching_usernames(is_user_active_mock):
    """
    Test refreshing an access token when the usernames in the access and refresh tokens do not match.
    """
    is_user_active_mock.return_value = True
    access_token = (
        "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InVzZXIxMjMiLCJleHAiOi02MjEzNTU5NjgwMH0.hMFgx83bidY-r2SVl"
        "p2fnKwzD-SaCbzfD054A_lRsEOyYYtSB52kBvnkp_oagYelXhEczfGGsfWzV_JkgalM-449KI99qImlab45ANyhriHoaDhMvs9ve_0TwPfD34z"
        "U3Y2PkcrgZ7lbYDqMArVOBDsAiO12ejYA7CAMjUBKgoXPIzMqup1Ah8Mzg0F5Gu2iUpoDfCyIt86KjAEiYk-CDm6w73b28BOaWaxk87tXUYXE6"
        "4KIWNkh99iXgYEDYvfSmvWdu6TCHtVmNzJ_Tb1egVHb-hO-3G62mnyHJ2x6p_k7Wq44JuGyC0SrRHWp-jZsubLvi_ikBDm6qgZ8mKcJxA"
    )

    jwt_handler = JWTHandler()
    with pytest.raises(JWTRefreshError) as exc:
        jwt_handler.refresh_access_token(access_token, VALID_REFRESH_TOKEN)
    assert str(exc.value) == "Unable to refresh access token"
    assert isinstance(exc.value.__cause__, UsernameMismatchError)
    assert str(exc.value.__cause__) == "The usernames in the access and refresh tokens do not match"


@patch("ldap_jwt_auth.auth.jwt_handler.Authorisation.is_active_user")
def test_refresh_access_token_with_not_active_username(is_user_active_mock):
    """
    Test refreshing an access token when username is not active.
    """
    is_user_active_mock.return_value = False

    jwt_handler = JWTHandler()
    with pytest.raises(JWTRefreshError) as exc:
        jwt_handler.refresh_access_token(EXPIRED_ACCESS_TOKEN, VALID_REFRESH_TOKEN)
    assert str(exc.value) == "Unable to refresh access token"
    assert isinstance(exc.value.__cause__, UserNotActiveError)
    assert str(exc.value.__cause__) == "The provided username 'username' is not part of the active usernames"


@patch("ldap_jwt_auth.auth.jwt_handler.Authorisation.is_active_user")
@patch("ldap_jwt_auth.auth.jwt_handler.datetime")
def test_refresh_access_token_with_valid_access_token(datetime_mock, is_user_active_mock):
    """
    Test refreshing a valid access token with a valid refresh token.
    """
    datetime_mock.now.return_value = mock_datetime_now()
    is_user_active_mock.return_value = True

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

    assert payload == {"username": "username", "role": "admin", "userIsAdmin": False, "exp": 253402300799}


def test_verify_token_with_refresh_token():
    """
    Test verifying a valid refresh token.
    """
    jwt_handler = JWTHandler()
    payload = jwt_handler.verify_token(VALID_REFRESH_TOKEN)

    assert payload == {"username": "username", "role": "admin", "userIsAdmin": False, "exp": 253402300799}


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
