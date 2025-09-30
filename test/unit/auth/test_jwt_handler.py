"""
Unit tests for the `JWTHandler` class.
"""

from datetime import datetime, timezone
from unittest.mock import patch

import pytest

from ldap_jwt_auth.auth.jwt_handler import JWTHandler
from ldap_jwt_auth.core.exceptions import InvalidJWTError, JWTRefreshError, UsernameMismatchError, UserNotActiveError

VALID_ACCESS_TOKEN = (
    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InVzZXJuYW1lIiwicm9sZXMiOlsiYWRtaW4iXSwidXNlcklzQWRtaW4iOnRyd"
    "WUsImV4cCI6MjUzNDAyMzAwNzk5fQ.gWXkZNeLCgNA04KhkGcAUB8WwrrVr8HMKp8yd9BUEBfDuiN1yekPxwKJ7LZDndHqYL4z9WWfVsDE5vYyWfjD"
    "JjhoymuP-VYTAI2GxbmazRmknsl9L-vRo31oPX3v2Cs5V2tcBv7dM49gzY7w-dS0b9QsOrn4Y1z9zLj4kLpVtNm0EhtbwThxMk8qVNNtEu76TAnYrd"
    "WAoz7_IedBh9NRf48EKJFfoh4CSbfXhHsGRZjvAKnjU-khaibWP3aWuMzN1nwQJ8WasgvhPaxMxd1qzKTbfpMMjg2eo3hDcQogU545P8zO4PcfzIid"
    "1g9hF1vMgRsAtQNK385oqBjYfOOWZw"
)

VALID_REFRESH_TOKEN = (
    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InVzZXJuYW1lIiwicm9sZXMiOlsiYWRtaW4iXSwidXNlcklzQWRtaW4iOnRyd"
    "WUsImV4cCI6MjUzNDAyMzAwNzk5fQ.gWXkZNeLCgNA04KhkGcAUB8WwrrVr8HMKp8yd9BUEBfDuiN1yekPxwKJ7LZDndHqYL4z9WWfVsDE5vYyWfjD"
    "JjhoymuP-VYTAI2GxbmazRmknsl9L-vRo31oPX3v2Cs5V2tcBv7dM49gzY7w-dS0b9QsOrn4Y1z9zLj4kLpVtNm0EhtbwThxMk8qVNNtEu76TAnYrd"
    "WAoz7_IedBh9NRf48EKJFfoh4CSbfXhHsGRZjvAKnjU-khaibWP3aWuMzN1nwQJ8WasgvhPaxMxd1qzKTbfpMMjg2eo3hDcQogU545P8zO4PcfzIid"
    "1g9hF1vMgRsAtQNK385oqBjYfOOWZw"
)
EXPIRED_ACCESS_TOKEN = (
    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InVzZXJuYW1lIiwicm9sZXMiOlsiYWRtaW4iXSwidXNlcklzQWRtaW4iOnRyd"
    "WUsImV4cCI6OTQ2Njg0Nzk5fQ.T9CEJWxCzvpuphZictOzaYVCJOEpO5eZ7T3EbYUE-AMUFNPzFJwYjuZVsA-rw-pNIAbUDfvlbYyMxx2ViII9XYjW"
    "0wLc3jJhpYz1t3kxhZI24NI5uReqZCtsiWLnRtVYeAjfRb8xgVH4ileEirR4xQLazBGNzN1KI8kYEcZ9m1253YUD5nsNcyz7cNirRoeSmfAi-kBU_z"
    "T7SuuP2NoVAKdhyX_tj-O44vzj8J-HK9YDxdLigiDZfTF2KVkPltDKe-ImumH9Z4zvHJMQC5Fq323VrjFp4WQn9cob-zYzS61s9jnqiikEsl89uLA-"
    "DlExviEnXIogsGL-6Qqq1_HldQ"
)

EXPIRED_REFRESH_TOKEN = (
    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InVzZXJuYW1lIiwicm9sZXMiOlsiYWRtaW4iXSwidXNlcklzQWRtaW4iOnRyd"
    "WUsImV4cCI6OTQ2Njg0Nzk5fQ.T9CEJWxCzvpuphZictOzaYVCJOEpO5eZ7T3EbYUE-AMUFNPzFJwYjuZVsA-rw-pNIAbUDfvlbYyMxx2ViII9XYjW"
    "0wLc3jJhpYz1t3kxhZI24NI5uReqZCtsiWLnRtVYeAjfRb8xgVH4ileEirR4xQLazBGNzN1KI8kYEcZ9m1253YUD5nsNcyz7cNirRoeSmfAi-kBU_z"
    "T7SuuP2NoVAKdhyX_tj-O44vzj8J-HK9YDxdLigiDZfTF2KVkPltDKe-ImumH9Z4zvHJMQC5Fq323VrjFp4WQn9cob-zYzS61s9jnqiikEsl89uLA-"
    "DlExviEnXIogsGL-6Qqq1_HldQ"
)

EXPECTED_ACCESS_TOKEN = (
    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InVzZXJuYW1lIiwicm9sZXMiOlsiYWRtaW4iXSwidXNlcklzQWRtaW4iOnRyd"
    "WUsImV4cCI6MTcwNTQ4NTkwMH0.CiKTW_7_1GG9vGyADwx1DW9m6rmqFpoGIqeDGN4TXZURVlRP9RvQhs6vBawDa2TTXEAzVno3rNBbycGdgFAu8JK"
    "Jk0h244PpBmTmUKxFGGTcZt1cSJ8-tEC0Yy3gZti9-DaG8S1ByQJ1b5IJE_gcDv6gXfUNurr2KWzeIh2ki_b_p96fj4Vexr5z1IsL9IEpb84_TzfQ6"
    "fEWaeIWGOXvCPHx4qMofNfo4GotF83vbN9tlYoZX11cuSQY-9q_v3yOt9r5azXqBDPeGLqX4kGhNZE40Y56Cbyqz-eWPfxQmuyiF0PNgu1-u2f4lx4"
    "pXKuYdDqbCFBnlwtrdr8vlm8xyA"
)

EXPECTED_REFRESH_TOKEN = (
    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InVzZXJuYW1lIiwicm9sZXMiOlsiYWRtaW4iXSwidXNlcklzQWRtaW4iOnRyd"
    "WUsImV4cCI6MTcwNjA5MDQwMH0.X7rHFpxSxySjKQs1RtL7U8whFEg8lLQbPTwt1DtokQpGdBgTyOcuLeK1Rf_PH1kgY54WaY6_MU4koirHwTp17VN"
    "k--M8YUSVhdG1q6gco6_Nbb-XWLigqWllVpDwNaKXZIPgtWZpCxc-Sz5OP7K6Oj0k0Zd8OIbP5KQM5H74jfoMxwfFHGJ3oJ5T3LdZTRmALRAsfXGqe"
    "bEzVUsbNEXTUzJ6dAexA-k8LgpRGcQyS6qQu5FmQXyxT-qW5cd9WaV4C3bMgGW7qO2jgSZ_VnYHl0ZlR7iDO-lRK4PqJ9uZ2tluJ173KLVW0AcX_zj"
    "dssstLT100wLKrx5DgwwCjTX4Qg"
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

    assert payload == {"username": "username", "roles": ["admin"], "userIsAdmin": True, "exp": 253402300799}


def test_verify_token_with_refresh_token():
    """
    Test verifying a valid refresh token.
    """
    jwt_handler = JWTHandler()
    payload = jwt_handler.verify_token(VALID_REFRESH_TOKEN)

    assert payload == {"username": "username", "roles": ["admin"], "userIsAdmin": True, "exp": 253402300799}


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
