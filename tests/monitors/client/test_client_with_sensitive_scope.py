import pytest
from unittest.mock import Mock

from kcwarden.monitors.client.client_with_sensitive_scope import ClientWithSensitiveScope
from kcwarden.custom_types import config_keys
from kcwarden.custom_types.keycloak_object import ClientScope


class TestClientWithSensitiveScope:
    @pytest.fixture
    def monitor(self, mock_database, default_config):
        monitor_instance = ClientWithSensitiveScope(mock_database, default_config)
        return monitor_instance

    def test_audit_default_scope(self, monitor, mock_scope, mock_client):
        mock_client.get_default_client_scopes.return_value = [mock_scope.get_name()]
        monitor._DB.get_all_clients.return_value = [mock_client]
        # fmt: off
        monitor._CONFIG = {
            config_keys.MONITOR_CONFIG: {
                "ClientWithSensitiveScope": [
                    {
                        "scope": mock_scope.get_name(),
                        "allowed": []
                    }
                ]
            },
            config_keys.AUDITOR_CONFIG: {}
        }
        # fmt: on
        results = list(monitor.audit())
        assert len(results) == 1
        assert results[0].to_dict()["entity"] == mock_client.get_name()

    def test_audit_optional_scope(self, monitor, mock_scope, mock_client):
        mock_client.get_optional_client_scopes.return_value = [mock_scope.get_name()]
        monitor._DB.get_all_clients.return_value = [mock_client]
        # fmt: off
        monitor._CONFIG = {
            config_keys.MONITOR_CONFIG: {
                "ClientWithSensitiveScope": [
                    {
                        "scope": mock_scope.get_name(),
                        "allowed": []
                    }
                ]
            },
            config_keys.AUDITOR_CONFIG: {}
        }
        # fmt: on
        results = list(monitor.audit())
        assert len(results) == 1
        assert results[0].to_dict()["entity"] == mock_client.get_name()

    def test_audit_regex_match(self, monitor, mock_scope, mock_client):
        mock_client.get_optional_client_scopes.return_value = [mock_scope.get_name()]
        monitor._DB.get_all_clients.return_value = [mock_client]
        # fmt: off
        monitor._CONFIG = {
            config_keys.MONITOR_CONFIG: {
                "ClientWithSensitiveScope": [
                    {
                        "scope": "sensitive-.*",
                        "allowed": []
                    }
                ]
            },
            config_keys.AUDITOR_CONFIG: {}
        }
        # fmt: on
        results = list(monitor.audit())
        assert len(results) == 1
        assert results[0].to_dict()["entity"] == mock_client.get_name()

    def test_audit_allowlist(self, monitor, mock_scope, mock_client):
        mock_client.get_optional_client_scopes.return_value = [mock_scope.get_name()]
        monitor._DB.get_all_clients.return_value = [mock_client]
        # fmt: off
        monitor._CONFIG = {
            config_keys.MONITOR_CONFIG: {
                "ClientWithSensitiveScope": [
                    {
                        "scope": "sensitive-.*",
                        "allowed": [mock_client.get_name()]
                    }
                ]
            },
            config_keys.AUDITOR_CONFIG: {}
        }
        # fmt: on
        results = list(monitor.audit())
        assert len(results) == 0

    def test_audit_allowlist_regex(self, monitor, mock_scope, mock_client):
        mock_client.get_optional_client_scopes.return_value = [mock_scope.get_name()]
        monitor._DB.get_all_clients.return_value = [mock_client]
        # fmt: off
        monitor._CONFIG = {
            config_keys.MONITOR_CONFIG: {
                "ClientWithSensitiveScope": [
                    {
                        "scope": "sensitive-.*",
                        "allowed": ["mock-.*"]
                    }
                ]
            },
            config_keys.AUDITOR_CONFIG: {}
        }
        # fmt: on
        results = list(monitor.audit())
        assert len(results) == 0

    @pytest.mark.parametrize(
        "ignore_disabled_clients, client_enabled, expected_result",
        [
            (True, False, 0),  # Disabled client, config to ignore
            (True, True, 1),  # Enabled client, should never be ignored
            (False, False, 1),  # Disabled client, config not to ignore
        ],
    )
    def test_ignore_disabled_client_when_asked(
        self, monitor, mock_client, ignore_disabled_clients, client_enabled, expected_result, mock_scope
    ):
        # fmt: off
        monitor._CONFIG = {
            config_keys.IGNORE_DISABLED_CLIENTS: ignore_disabled_clients,
            config_keys.MONITOR_CONFIG: {
                "ClientWithSensitiveScope": [
                    {
                        "scope": "sensitive-.*",
                        "allowed": []
                    }
                ]
            },
            config_keys.AUDITOR_CONFIG: {}
        }
        # fmt: on
        mock_client.is_enabled.return_value = client_enabled
        mock_client.get_optional_client_scopes.return_value = [mock_scope.get_name()]
        monitor._DB.get_all_clients.return_value = [mock_client]

        results = list(monitor.audit())
        assert len(results) == expected_result
