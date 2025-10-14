"""
Module providing test fixtures for the e2e tests.
"""

import pytest
from fastapi.testclient import TestClient

from ldap_jwt_auth.main import app


@pytest.fixture(scope="package", name="test_client")
def fixture_test_client() -> TestClient:
    """
    Fixture for creating a test client for the application.

    :return: The test client.
    """
    return TestClient(app)
