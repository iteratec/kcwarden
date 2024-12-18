import pytest
from unittest.mock import Mock

from kcwarden.monitors.protocol_mapper.protocol_mapper_with_config import ProtocolMapperWithConfig
from kcwarden.custom_types.keycloak_object import ClientScope
from kcwarden.custom_types import config_keys


class TestProtocolMapperWithConfig:
    @pytest.fixture
    def monitor(self, database, default_config):
        monitor_instance = ProtocolMapperWithConfig(database, default_config)
        monitor_instance._DB = Mock()
        return monitor_instance

    def test_protocol_mapper_matches_config(self, monitor, mock_protocol_mapper):
        # Test case where both type and config match
        assert monitor._protocol_mapper_matches_config(
            mock_protocol_mapper,
            "oidc-usermodel-attribute-mapper",
            {"userinfo.token.claim": "true", "user.attribute": "email"},
        )

        # Test case where type matches but config doesn't
        assert not monitor._protocol_mapper_matches_config(
            mock_protocol_mapper,
            "oidc-usermodel-attribute-mapper",
            {"userinfo.token.claim": "false", "user.attribute": "username"},
        )

        # Test case where type doesn't match
        assert not monitor._protocol_mapper_matches_config(
            mock_protocol_mapper, "oidc-audience-mapper", {"userinfo.token.claim": "true", "user.attribute": "email"}
        )

        # Test case with regex in type
        assert monitor._protocol_mapper_matches_config(
            mock_protocol_mapper, "oidc-.*-mapper", {"userinfo.token.claim": "true", "user.attribute": "email"}
        )

        # Test case with regex in config
        assert monitor._protocol_mapper_matches_config(
            mock_protocol_mapper,
            "oidc-usermodel-attribute-mapper",
            {"userinfo.token.claim": "tr.*", "user.attribute": "em.*"},
        )

        # Test case with empty config
        assert monitor._protocol_mapper_matches_config(mock_protocol_mapper, "oidc-usermodel-attribute-mapper", {})

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

    def test_audit_no_matches(self, monitor, mock_client):
        monitor._DB.get_all_clients.return_value = [mock_client]
        monitor.get_custom_config = Mock(
            return_value=[
                {
                    "protocol-mapper-type": "oidc-usermodel-attribute-mapper",
                    "matched-config": {"userinfo.token.claim": "true"},
                    "allowed": [],
                }
            ]
        )

        results = list(monitor.audit())
        assert len(results) == 0

    def test_audit_client_match(self, monitor, mock_client, mock_protocol_mapper):
        mock_client.get_protocol_mappers.return_value = [mock_protocol_mapper]
        monitor._DB.get_all_clients.return_value = [mock_client]
        monitor.get_custom_config = Mock(
            return_value=[
                {
                    "protocol-mapper-type": "oidc-usermodel-attribute-mapper",
                    "matched-config": {"userinfo.token.claim": "true"},
                    "allowed": [],
                }
            ]
        )

        results = list(monitor.audit())
        assert len(results) == 1
        assert results[0].to_dict()["entity"] == mock_client.get_name()

    def test_audit_scope_match(self, monitor, mock_client, mock_scope, mock_protocol_mapper):
        mock_client.get_default_client_scopes.return_value = ["test-scope"]
        mock_scope.get_protocol_mappers.return_value = [mock_protocol_mapper]
        monitor._DB.get_all_clients.return_value = [mock_client]
        monitor._DB.get_scope.return_value = mock_scope
        monitor.get_custom_config = Mock(
            return_value=[
                {
                    "protocol-mapper-type": "oidc-usermodel-attribute-mapper",
                    "matched-config": {"userinfo.token.claim": "true"},
                    "allowed": [],
                }
            ]
        )

        results = list(monitor.audit())
        assert len(results) == 1
        assert results[0].to_dict()["entity"] == mock_client.get_name()

    def test_audit_allowed_client(self, monitor, mock_client, mock_protocol_mapper):
        mock_client.get_protocol_mappers.return_value = [mock_protocol_mapper]
        monitor._DB.get_all_clients.return_value = [mock_client]
        monitor.get_custom_config = Mock(
            return_value=[
                {
                    "protocol-mapper-type": "oidc-usermodel-attribute-mapper",
                    "matched-config": {"userinfo.token.claim": "true"},
                    "allowed": [mock_client.get_name()],
                }
            ]
        )

        results = list(monitor.audit())
        assert len(results) == 0

    def test_audit_multiple_configs(self, monitor, mock_client, mock_protocol_mapper):
        mock_client.get_protocol_mappers.return_value = [mock_protocol_mapper]
        monitor._DB.get_all_clients.return_value = [mock_client]
        monitor.get_custom_config = Mock(
            return_value=[
                {
                    "protocol-mapper-type": "oidc-usermodel-attribute-mapper",
                    "matched-config": {"userinfo.token.claim": "true"},
                    "allowed": [],
                },
                {"protocol-mapper-type": "oidc-audience-mapper", "matched-config": {}, "allowed": []},
            ]
        )

        results = list(monitor.audit())
        assert len(results) == 1
        assert results[0].to_dict()["entity"] == mock_client.get_name()
