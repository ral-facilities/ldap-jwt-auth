"""
Unit tests for the `JWTHandler` class.
"""

from datetime import datetime, timezone
from unittest.mock import patch

import pytest

from ldap_jwt_auth.auth.jwt_handler import JWTHandler
from ldap_jwt_auth.core.exceptions import InvalidJWTError, JWTRefreshError, UsernameMismatchError, UserNotActiveError

VALID_ACCESS_TOKEN = (
    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InVzZXJuYW1lIiwicm9sZSI6ImFkbWluIiwidXNlcklzQWRtaW4iOnRydWUsI"
    "mV4cCI6MjUzNDAyMzAwNzk5fQ.e_yNd4axueRx9_4rG05tWNHiUkwsoZUsNdpl8vb5ofHiFkJAB7D2Gy6NJmg9Pg4fKxpGS-HqRfCjrtQiWX-ZM3UC"
    "J3S468bWk_DEpEeift3wfp8Kmha3iEgAYruMta7RaoWeeyYMVqq581zHhb8zCquMfFz30R-VKZw_MQidvhK1G3QpwAs-kwcCLgugZi3C2kw5JBDm_j"
    "QlyyGiK06C_X5c4tGSvpgMFz0ex6gAr6QcEX9kkS7TKrLySoL5DC_ElKrjOs24QhPO2xlKOw82rfJa7wRpARWFdbY0NFy7veAiQfzlfW_9X_Mas2gR"
    "MF6tu6pkTnVRoLIv07l-nukjlA"
)

VALID_REFRESH_TOKEN = (
    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InVzZXJuYW1lIiwicm9sZSI6ImFkbWluIiwidXNlcklzQWRtaW4iOnRydWUsI"
    "mV4cCI6MjUzNDAyMzAwNzk5fQ.e_yNd4axueRx9_4rG05tWNHiUkwsoZUsNdpl8vb5ofHiFkJAB7D2Gy6NJmg9Pg4fKxpGS-HqRfCjrtQiWX-ZM3UC"
    "J3S468bWk_DEpEeift3wfp8Kmha3iEgAYruMta7RaoWeeyYMVqq581zHhb8zCquMfFz30R-VKZw_MQidvhK1G3QpwAs-kwcCLgugZi3C2kw5JBDm_j"
    "QlyyGiK06C_X5c4tGSvpgMFz0ex6gAr6QcEX9kkS7TKrLySoL5DC_ElKrjOs24QhPO2xlKOw82rfJa7wRpARWFdbY0NFy7veAiQfzlfW_9X_Mas2gR"
    "MF6tu6pkTnVRoLIv07l-nukjlA"
)
EXPIRED_ACCESS_TOKEN = (
    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InVzZXJuYW1lIiwicm9sZSI6ImFkbWluIiwidXNlcklzQWRtaW4iOnRydWUsI"
    "mV4cCI6OTQ2Njg0Nzk5fQ.Uy2rbVeoGNOGu0SiXXj3EFAymzSNzMarEebThpvwKBDUKFefxyUboxxpPwngEG0rvLjIDF1Q_tioUYC68vqxtFx7Zchw"
    "YrqAvje_rK86NOvr-Xh_Z9t2NAjLYcVApQ3X6_fefSzu4p6-JBwMGs32hsusuS5wCsejxY7-6e5kIIWRgkG9NYK2KL-xrj-KtIZfUnAJVzGl4fnUfS"
    "xfXap-rg1z-IXvPWuUpPPheRhkqs2_9tohhZN-n0rJjJXolCiJJp4zSXUVxnKfgpYb9_0ddQnNdHfptNHdUb3S92zwBgy2uQFTKsD650EgJhKlxYBh"
    "xN2RBIaL7CnUjJENEvMy8g"
)

EXPIRED_REFRESH_TOKEN = (
    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InVzZXJuYW1lIiwicm9sZSI6ImFkbWluIiwidXNlcklzQWRtaW4iOnRydWUsI"
    "mV4cCI6OTQ2Njg0Nzk5fQ.Uy2rbVeoGNOGu0SiXXj3EFAymzSNzMarEebThpvwKBDUKFefxyUboxxpPwngEG0rvLjIDF1Q_tioUYC68vqxtFx7Zchw"
    "YrqAvje_rK86NOvr-Xh_Z9t2NAjLYcVApQ3X6_fefSzu4p6-JBwMGs32hsusuS5wCsejxY7-6e5kIIWRgkG9NYK2KL-xrj-KtIZfUnAJVzGl4fnUfS"
    "xfXap-rg1z-IXvPWuUpPPheRhkqs2_9tohhZN-n0rJjJXolCiJJp4zSXUVxnKfgpYb9_0ddQnNdHfptNHdUb3S92zwBgy2uQFTKsD650EgJhKlxYBh"
    "xN2RBIaL7CnUjJENEvMy8g"
)

EXPECTED_ACCESS_TOKEN = (
    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InVzZXJuYW1lIiwicm9sZSI6ImFkbWluIiwidXNlcklzQWRtaW4iOnRydWUsI"
    "mV4cCI6MTcwNTQ4NTkwMH0.RYwoZe60ONHwkzM73U25wO6XrRPCj-2szv-ceUIkRVISl--2wdVdAWoJCprSt958OxZN7ZjEDt3TssyANcebCBCHQ5Q"
    "BSmwh9XanNv_Uhi2I5vauKQdQqeo2N0h3TA5rwkgUOGD771wUggctF-ucPHMciwyT8AfICOTFSdT46g6tLE7svI5NDaL_S7DEugRhRbrFtxsTAUOBG"
    "qF6gZs9J4Svqx8QLtx3KB5gHl9NtsBlrhNrTgytsnMGXGm8MOG0AKxqWwCPTxZfRiI8IUDDDvJK8IUWUKFr8-M-Hl-dDFc4L2hhAcWdDYzHjCUEtMH"
    "p5Js1SZgrT35oQ-SgH2mXnQ"
)

EXPECTED_REFRESH_TOKEN = (
    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InVzZXJuYW1lIiwicm9sZSI6ImFkbWluIiwidXNlcklzQWRtaW4iOnRydWUsI"
    "mV4cCI6MTcwNjA5MDQwMH0.szn7TJsxeNcIWabT9mzEHx3XeYsGeGpIPS8mZeDC0e_KehhF0p-MgZB0grz4I7F7cqe2rOFo9GFk_kfmHfH2PBdl_fx"
    "haxvnGb3PhWl9zEUXqh03HMXXgZlv9IGw6s4kaNPDmArU6ILsrEj_sXiXuiuD_okky_eboozXUIYFQG6xRdlvH6ujNA_cJpkeCk6dMiQoafm648LkE"
    "x2kkEqq4zQCyhZwhC8K17itXCs3JjJ63YQZoxjbdDyike3J8eMDhtEwZarUl62D5OlTDnRVulB6sVGzsLRWEssXfsZHEGPEQhQd9lbaiFafbfPbQg8"
    "DUBTnCKvKWqX2pOmGxA_rYg"
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

    assert payload == {"username": "username", "role": "admin", "userIsAdmin": True, "exp": 253402300799}


def test_verify_token_with_refresh_token():
    """
    Test verifying a valid refresh token.
    """
    jwt_handler = JWTHandler()
    payload = jwt_handler.verify_token(VALID_REFRESH_TOKEN)

    assert payload == {"username": "username", "role": "admin", "userIsAdmin": True, "exp": 253402300799}


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
