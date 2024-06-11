"""
Unit tests for the `JWTHandler` class.
"""

from datetime import datetime, timezone
from unittest.mock import patch

import pytest

from ldap_jwt_auth.auth.jwt_handler import JWTHandler
from ldap_jwt_auth.core.exceptions import InvalidJWTError, JWTRefreshError, UsernameMismatchError, UserNotActiveError

VALID_ACCESS_TOKEN = (
    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InVzZXJuYW1lIiwiZXhwIjoyNTM0MDE2OTU5OTl9.nqT4Ct4VpdcDCv1Yd8M5"
    "I2LWWfN9or2N6C3jnNbxyq90z8jysZfkEQ5ZIPMDV2KgI4E7E44qYzLpqirAw2EKp03vZyE28G0XkEYAA1KlDlgDw5C3AdN_dfaR1xD3HjgQVII2zW"
    "5P5Wp8DfGV174KI8g-InzvOAMSl9e5Ci1S6ewqkUDhrUnvsAKZzqdYM-oewrySnTiRfP-eQOaR0MBBKjURaJeh9mWDiQFdfqh_4vwauI7FiCj2R0Z0"
    "IySTTR6_R-Jw2h1EUxrHVioqK9vlY6fi96jp9BmSET17n0j06wunkz8MJg8i479VjqtQL0e_if6cm3zOHRZJ7iTXicHmSg"
)

VALID_REFRESH_TOKEN = (
    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InVzZXJuYW1lIiwiZXhwIjoyNTM0MDIzMDA3OTl9.bagU2Wix8wKzydVU_L3Z"
    "ZuuMAxGxV4OTuZq_kS2Fuwm839_8UZOkICnPTkkpvsm1je0AWJaIXLGgwEa5zUjpG6lTrMMmzR9Zi63F0NXpJqQqoOZpTBMYBaggsXqFkdsv-yAKUZ"
    "8MfjCEyk3UZ4PXZmEcUZcLhKcXZr4kYJPjio2e5WOGpdjK6q7s-iHGs9DQFT_IoCnw9CkyOKwYdgpB35hIGHkNjiwVSHpyKbFQvzJmIv5XCTSRYqq0"
    "1fldh-QYuZqZeuaFidKbLRH610o2-1IfPMUr-yPtj5PZ-AaX-XTLkuMqdVMCk0_jeW9Os2BPtyUDkpcu1fvW3_S6_dK3nQ"
)

EXPIRED_ACCESS_TOKEN = (
    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InVzZXJuYW1lIiwiZXhwIjotNjIxMzU1OTY4MDB9.G_cfC8PNYE5yERyyQNRk"
    "9mTmDusU_rEPgm7feo2lWQF6QMNnf8PUN-61FfMNRVE0QDSvAmIMMNEOa8ma0JHZARafgnYJfn1_FSJSoRxC740GpG8EFSWrpM-dQXnoD263V9FlK-"
    "On6IbhF-4Rh9MdoxNyZk2Lj7NvCzJ7gbgbgYM5-sJXLxB-I5LfMfuYM3fx2cRixZFA153l46tFzcMVBrAiBxl_LdyxTIOPfHF0UGlaW2UtFi02gyBU"
    "4E4wTOqPc4t_CSi1oBSbY7h9O63i8IU99YsOCdvZ7AD3ePxyM1xJR7CFHycg9Z_IDouYnJmXpTpbFMMl7SjME3cVMfMrAQ"
)

EXPIRED_REFRESH_TOKEN = (
    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InVzZXJuYW1lIiwiZXhwIjotNjIxMzQ5OTIwMDB9.Xu6Tnh_NVQjHAXiRyhAz"
    "L8yIVeon3nO6lQfX2Ct928dBDbUI5jG2ZrA0EyoeMPRuJIqv0gVg3L561A547mx2aVkzJmemqIIYgaUd4uOZWU5dyLp0Y9Tx2oMaSQBiK_HDoWo4dw"
    "1XVcvZXhw08J3CCvrCIGwwcQKuTg0u43G9_shPr_1Ntdg5Z7hLiYMlKVilYtWBV0JsPq28qQ4m7m-Fe9l27l033YjtmxvgmGlDw2PA6DIHnxxSxpB3"
    "aXPzty4sReU6uWwx5-XpjnHtctCe99lefsqHCA8LNlW915PyRsCQOylQo0IM-aNp2WvITdUj4ZNIgZ4KigR28BRj1NMpSA"
)

EXPECTED_ACCESS_TOKEN = (
    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InVzZXJuYW1lIiwiZXhwIjoxNzA1NDg1OTAwfQ.aWJ8T8RGHF93YhRSP9nOAD"
    "EKY9nFjVIDu7RQhPGiMpvhgdpPBP17VQPbJ6Smt8mG1TjLXjquJZaDQRF7syrJd8ESDo-lh3ef-cMWg2hWZpbtpQaPaNHLAAMrjZo97qLxrBjeOKjY"
    "ggqwKMr-7g_LlB--z9GiQrLJVhpGxAXjnTy9VSrioZIU7OE9L9tUyOI7LGjY0X2znWQ3Loy5sMwCP_SeFHBPolKXiErKeLItriaxYNEc5l5VXD2wsK"
    "G9L8dDZZwe4BSU2eyT_2hhPTrVNfI8-J1KtwpLywC0NfS0Vaksy4HG2IbH8hpl6gaLZhtr2C5_0H_IpkTsvm_Zsnzhbg"
)

EXPECTED_REFRESH_TOKEN = (
    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InVzZXJuYW1lIiwiZXhwIjoxNzA2MDkwNDAwfQ.OPl4pB7_fIGYB80782b0iG"
    "nFToF5HoYAUjVSfU521KHyeDvXTSrbwVod8_-8Js9aiQlXyA-sTwtfbic6jc6tLiB0vOJ3l12152QqMok8_h7tY2nJ1UjLoPWI-QQ9m2JkOHu8TWRM"
    "DmbtcJ4X2_7h7AcJyW08ORMWQNJq9PjIEb8HXJlkyd3SMiak2HxYjFik1wbjq3Q3RGN8IQdCTiPu_bB6Rot5vH5_q4JQ9CKCgEt7Mc6ZntED14I1rc"
    "okx3dwI2GFhpGPJfW87PZqCsJC1fgSPHQoEs1o_prRmEIOzFT2x343mCjHJwwxYXyMh5xq0A-_6_b74bLbO2HEa68EEw"
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


@patch("ldap_jwt_auth.auth.jwt_handler.Authentication.is_user_active")
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


@patch("ldap_jwt_auth.auth.jwt_handler.Authentication.is_user_active")
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


@patch("ldap_jwt_auth.auth.jwt_handler.Authentication.is_user_active")
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


@patch("ldap_jwt_auth.auth.jwt_handler.Authentication.is_user_active")
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

    assert payload == {"username": "username", "exp": 253401695999}


def test_verify_token_with_refresh_token():
    """
    Test verifying a valid refresh token.
    """
    jwt_handler = JWTHandler()
    payload = jwt_handler.verify_token(VALID_REFRESH_TOKEN)

    assert payload == {"username": "username", "exp": 253402300799}


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
