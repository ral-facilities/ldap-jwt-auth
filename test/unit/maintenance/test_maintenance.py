"""
Unit tests for the `Maintenance` class.
"""

import json

from unittest.mock import mock_open, patch

import pytest
from ldap_jwt_auth.core.exceptions import InvalidMaintenanceFileError, MaintenanceFileReadError
from ldap_jwt_auth.core.maintenance import Maintenance


class TestMaintenance:
    """Tests for the `Maintenance` class."""

    def test_get_maintenance_state(self):
        """
        Test returning maintenance state schema.
        """
        mock_maintenance_data = {"show": True, "message": "This is a test message"}
        mock_maintenance_file = json.dumps(mock_maintenance_data)

        with (
            patch("builtins.open", mock_open(read_data=mock_maintenance_file)),
            patch("json.load", return_value=mock_maintenance_data),
        ):
            maintenance = Maintenance()
            response = maintenance.get_maintenance_state()

        assert response.show is True
        assert response.message == "This is a test message"

    def test_get_maintenance_state_invalid_file(self):
        """
        Test returning maintenance state schema when file is invalid.
        """
        mock_maintenance_data = {"show": "test", "message": False}
        mock_maintenance_file = json.dumps(mock_maintenance_data)

        with (
            patch("builtins.open", mock_open(read_data=mock_maintenance_file)),
            patch("json.load", return_value=mock_maintenance_data),
        ):
            maintenance = Maintenance()

            with pytest.raises(InvalidMaintenanceFileError) as exc:
                maintenance.get_maintenance_state()
            assert str(exc.value) == "An error occurred while validating the data in the maintenance file"

    def test_get_maintenance_state_missing_file(self):
        """
        Test returning maintenance state schema when file is missing.
        """
        with patch("builtins.open", mock_open()) as mocked_open:
            mocked_open.side_effect = IOError
            maintenance = Maintenance()

            with pytest.raises(MaintenanceFileReadError) as exc:
                maintenance.get_maintenance_state()
            assert str(exc.value) == "An error occurred while trying to find and read the maintenance file"

    def test_get_scheduled_maintenance_state(self):
        """
        Test returning scheduled maintenance state schema.
        """
        mock_scheduled_maintenance_data = {"show": True, "message": "This is a test message"}
        mock_scheduled_maintenance_file = json.dumps(mock_scheduled_maintenance_data)

        with (
            patch("builtins.open", mock_open(read_data=mock_scheduled_maintenance_file)),
            patch("json.load", return_value=mock_scheduled_maintenance_data),
        ):
            maintenance = Maintenance()
            response = maintenance.get_scheduled_maintenance_state()

        assert response.show is True
        assert response.message == "This is a test message"

    def test_get_scheduled_maintenance_state_invalid_file(self):
        """
        Test returning scheduled maintenance state schema when file is invalid.
        """
        mock_scheduled_maintenance_data = {"show": None, "message": "This is a test message"}
        mock_scheduled_maintenance_file = json.dumps(mock_scheduled_maintenance_data)

        with (
            patch("builtins.open", mock_open(read_data=mock_scheduled_maintenance_file)),
            patch("json.load", return_value=mock_scheduled_maintenance_data),
        ):
            maintenance = Maintenance()

            with pytest.raises(InvalidMaintenanceFileError) as exc:
                maintenance.get_scheduled_maintenance_state()
            assert str(exc.value) == "An error occurred while validating the data in the scheduled maintenance file"

    def test_get_scheduled_maintenance_state_missing_file(self):
        """
        Test returning scheduled maintenance state schema when file is missing.
        """
        with patch("builtins.open", mock_open()) as mocked_open:
            mocked_open.side_effect = IOError
            maintenance = Maintenance()

            with pytest.raises(MaintenanceFileReadError) as exc:
                maintenance.get_scheduled_maintenance_state()
            assert str(exc.value) == "An error occurred while trying to find and read the scheduled maintenance file"
