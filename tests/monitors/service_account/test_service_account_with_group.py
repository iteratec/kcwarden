import pytest
from unittest.mock import Mock

from kcwarden.monitors.service_account.service_account_with_group import ServiceAccountWithGroup
from kcwarden.custom_types import config_keys


class TestServiceAccountWithGroup:
    @pytest.fixture
    def monitor(self, database, default_config):
        monitor_instance = ServiceAccountWithGroup(database, default_config)
        monitor_instance._DB = Mock()
        return monitor_instance

    @pytest.fixture
    def mock_service_account(self):
        service_account = Mock()
        service_account.get_username.return_value = "test-service-account"
        service_account.get_client_id.return_value = "test-client-id"
        service_account.get_groups.return_value = ["test-group"]
        return service_account

    # Unit tests using Mocks
    def test_should_consider_service_account(self, monitor, mock_service_account):
        allowed_service_accounts = ["allowed-.*"]
        assert monitor._should_consider_service_account(mock_service_account, allowed_service_accounts) is True

        mock_service_account.get_username.return_value = "allowed-service-account"
        assert monitor._should_consider_service_account(mock_service_account, allowed_service_accounts) is False

    @pytest.mark.parametrize(
        "ignore_disabled_clients, client_enabled, expected_result, is_client_object",
        [
            (True, False, True, True),  # Disabled client, config to ignore
            (True, True, False, True),  # Enabled client, should never be ignored
            (False, False, False, True),  # Disabled client, config not to ignore
            (True, False, False, False),  # Non-Client object, should always return False
        ],
    )
    def test_is_ignored_disabled_client(
        self, monitor, mock_client, ignore_disabled_clients, client_enabled, expected_result, is_client_object
    ):
        monitor._CONFIG = {config_keys.IGNORE_DISABLED_CLIENTS: ignore_disabled_clients}

        if is_client_object:
            mock_client.is_enabled.return_value = client_enabled
            test_object = mock_client
        else:
            test_object = Mock()  # Non-Client object
        assert monitor.is_ignored_disabled_client(test_object) is expected_result

    # More comprehensive overall tests using a real realm export
    def test_find_sensitive_group(self, example_db):
        # Test everything with the default settings
        # fmt: off
        # I'd like to keep this readable
        config = {
            "monitors": {
                "ServiceAccountWithGroup": [
                    {
                        "allowed": [],
                        "group": "/sensitive-group",
                        "allow_no_group": True,
                    }
                ]
            }
        }
        # fmt: on
        monitor = ServiceAccountWithGroup(example_db, config)
        results = [result for result in monitor.audit()]
        assert len(results) == 1
        for result in results:
            assert result.to_dict()["entity"] == "service-account-client-with-service-account-in-sensitive-group"

    def test_do_not_allow_no_group(self, example_db):
        # fmt: off
        # I'd like to keep this readable
        config = {
            "monitors": {
                "ServiceAccountWithGroup": [
                    {
                        "allowed": [],
                        "group": "/sensitive-group",
                        "allow_no_group": False,
                    }
                ]
            }
        }
        # fmt: on
        monitor = ServiceAccountWithGroup(example_db, config)
        results = [result for result in monitor.audit()]
        assert len(results) == 5

    def test_allow_list_string(self, example_db):
        # fmt: off
        # I'd like to keep this readable
        config = {
            "monitors": {
                "ServiceAccountWithGroup": [
                    {
                        "allowed": ["service-account-client-with-service-account-in-sensitive-group"],
                        "group": "/sensitive-group",
                        "allow_no_group": True,
                    }
                ]
            }
        }
        # fmt: on
        monitor = ServiceAccountWithGroup(example_db, config)
        results = [result for result in monitor.audit()]
        assert len(results) == 0

    def test_allow_list_regex(self, example_db):
        # fmt: off
        # I'd like to keep this readable
        config = {
            "monitors": {
                "ServiceAccountWithGroup": [
                    {
                        "allowed": [".*-sensitive-group$"],
                        "group": "/sensitive-group",
                        "allow_no_group": True
                    }
                ]
            }
        }
        # fmt: on
        monitor = ServiceAccountWithGroup(example_db, config)
        results = [result for result in monitor.audit()]
        assert len(results) == 0

    def test_multiple_monitor_definitions(self, example_db):
        config = {
            "monitors": {
                "ServiceAccountWithGroup": [
                    {
                        "allowed": [],
                        "group": "/sensitive-group",
                        "allow_no_group": True,
                    },
                    {
                        "allowed": [],
                        "group": "/benign-group",
                        "allow_no_group": True,
                    },
                ]
            }
        }
        monitor = ServiceAccountWithGroup(example_db, config)
        results = [result for result in monitor.audit()]
        assert len(results) == 2

    def test_regex_matching_monitored_group(self, example_db):
        config = {
            "monitors": {
                "ServiceAccountWithGroup": [
                    {
                        "allowed": [],
                        "group": ".*sensitive.*",
                        "allow_no_group": True,
                    }
                ]
            }
        }
        monitor = ServiceAccountWithGroup(example_db, config)
        results = [result for result in monitor.audit()]
        assert len(results) == 4

    def test_additional_details_in_findings(self, example_db):
        config = {
            "monitors": {
                "ServiceAccountWithGroup": [
                    {
                        "allowed": [],
                        "group": "/sensitive-group",
                        "allow_no_group": True,
                    }
                ]
            }
        }
        monitor = ServiceAccountWithGroup(example_db, config)
        results = [result for result in monitor.audit()]
        for result in results:
            assert "monitored_group" in result.to_dict()["additional_details"]
            assert "assigned_groups" in result.to_dict()["additional_details"]
