import pytest
from unittest.mock import Mock

from kcwarden.monitors.service_account.service_account_with_sensitive_role import ServiceAccountWithSensitiveRole
from kcwarden.custom_types import config_keys


class TestServiceAccountWithSensitiveRole:
    @pytest.fixture
    def monitor(self, database, default_config):
        monitor_instance = ServiceAccountWithSensitiveRole(database, default_config)
        monitor_instance._DB = Mock()
        return monitor_instance

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
    def test_find_sensitive_role(self, example_db):
        # Test everything with the default settings
        # fmt: off
        # I'd like to keep this readable
        config = {
            "monitors": {
                "ServiceAccountWithSensitiveRole": [
                    {
                        "allowed": [],
                        "role": "sensitive-role",
                        "role-client": "realm"
                    }
                ]
            }
        }
        # fmt: on
        monitor = ServiceAccountWithSensitiveRole(example_db, config)
        results = [result for result in monitor.audit()]
        assert len(results) == 7
        for result in results:
            assert result.to_dict()["entity"] in [
                "service-account-client-with-service-account-with-sensitive-role",
                "service-account-client-with-service-account-with-sensitive-composite-role",
                "service-account-client-with-service-account-with-recursive-sensitive-role",
                "service-account-service-account-client-with-service-account-in-sensitive-subgroup",
                "service-account-client-with-service-account-in-recursive-sensitive-group",
                "service-account-client-with-service-account-in-subgroup-of-sensitive-composite-group",
                "service-account-client-with-service-account-in-sensitive-group",
            ]

    def test_ignore_specific_entity(self, example_db):
        # fmt: off
        config = {
            "monitors": {
                "ServiceAccountWithSensitiveRole": [
                    {
                        "allowed": ["service-account-client-with-service-account-with-sensitive-role"],
                        "role": "sensitive-role",
                        "role-client": "realm"
                    }
                ]
            }
        }
        # fmt: on
        monitor = ServiceAccountWithSensitiveRole(example_db, config)
        results = [result for result in monitor.audit()]
        assert len(results) == 6
        for result in results:
            assert result.to_dict()["entity"] in [
                "service-account-client-with-service-account-with-sensitive-composite-role",
                "service-account-client-with-service-account-with-recursive-sensitive-role",
                "service-account-service-account-client-with-service-account-in-sensitive-subgroup",
                "service-account-client-with-service-account-in-recursive-sensitive-group",
                "service-account-client-with-service-account-in-subgroup-of-sensitive-composite-group",
                "service-account-client-with-service-account-in-sensitive-group",
            ], result.to_dict()["entity"]

    def test_ignore_by_regex(self, example_db):
        # fmt: off
        config = {
            "monitors": {
                "ServiceAccountWithSensitiveRole": [
                    {
                        "allowed": ["service-account-client-with-service-account-with-.*"],
                        "role": "sensitive-role",
                        "role-client": "realm"
                    }
                ]
            }
        }
        # fmt: on
        monitor = ServiceAccountWithSensitiveRole(example_db, config)
        results = [result for result in monitor.audit()]
        assert len(results) == 4
        for result in results:
            assert result.to_dict()["entity"] in [
                "service-account-service-account-client-with-service-account-in-sensitive-subgroup",
                "service-account-client-with-service-account-in-recursive-sensitive-group",
                "service-account-client-with-service-account-in-subgroup-of-sensitive-composite-group",
                "service-account-client-with-service-account-in-sensitive-group",
            ]

    def test_match_role_by_regex(self, example_db):
        # fmt: off
        config = {
            "monitors": {
                "ServiceAccountWithSensitiveRole": [
                    {
                        "allowed": [],
                        "role": ".*-role$",
                        "role-client": "realm"
                    }
                ]
            }
        }
        # fmt: on
        monitor = ServiceAccountWithSensitiveRole(example_db, config)
        results = [result for result in monitor.audit()]
        assert len(results) == 16

    @pytest.mark.parametrize(
        "ignore_disabled_clients, expected_number",
        [
            (True, 6),  # When ignoring disabled clients, we expect to find 4
            (False, 7),  # When explicitly not ignoring them, we expect 5
            (None, 7),  # When the value is not set, do not ignore by default
        ],
    )
    def test_ignore_disabled_client(self, example_db, ignore_disabled_clients, expected_number):
        # Ignore a specific entity
        # fmt: off
        config = {
            "ignore_disabled_clients": ignore_disabled_clients,
            "monitors": {
                "ServiceAccountWithSensitiveRole": [
                    {
                        "allowed": [],
                        "role": "sensitive-role",
                        "role-client": "realm"
                    }
                ]
            }
        }
        # fmt: on
        example_db.get_client("client-with-service-account-with-sensitive-role")._d["enabled"] = False
        monitor = ServiceAccountWithSensitiveRole(example_db, config)
        results = [result for result in monitor.audit()]
        assert len(results) == expected_number
