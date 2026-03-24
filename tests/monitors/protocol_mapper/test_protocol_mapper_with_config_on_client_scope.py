import pytest
from unittest.mock import Mock

from kcwarden.monitors.protocol_mapper.protocol_mapper_with_config_on_client_scope import (
    ProtocolMapperWithConfigOnClientScope,
)


class TestProtocolMapperWithConfigOnClientScope:
    @pytest.fixture
    def monitor(self, database, default_config):
        monitor_instance = ProtocolMapperWithConfigOnClientScope(database, default_config)
        monitor_instance._DB = Mock()
        return monitor_instance

    def test_protocol_mapper_matches_config(self, monitor, mock_protocol_mapper):
        # Both type and config match
        assert monitor._protocol_mapper_matches_config(
            mock_protocol_mapper,
            "oidc-usermodel-attribute-mapper",
            {"userinfo.token.claim": "true", "user.attribute": "email"},
        )

        # Type matches but config doesn't
        assert not monitor._protocol_mapper_matches_config(
            mock_protocol_mapper,
            "oidc-usermodel-attribute-mapper",
            {"userinfo.token.claim": "false"},
        )

        # Type doesn't match
        assert not monitor._protocol_mapper_matches_config(mock_protocol_mapper, "oidc-audience-mapper", {})

        # Regex in type
        assert monitor._protocol_mapper_matches_config(
            mock_protocol_mapper, "oidc-.*-mapper", {"userinfo.token.claim": "true"}
        )

        # Empty config matches any mapper of that type
        assert monitor._protocol_mapper_matches_config(mock_protocol_mapper, "oidc-usermodel-attribute-mapper", {})

    def test_audit_no_matches(self, monitor, mock_scope):
        monitor._DB.get_all_scopes.return_value = [mock_scope]
        monitor.get_custom_config = Mock(
            return_value=[
                {
                    "protocol-mapper-type": "oidc-audience-mapper",
                    "matched-config": {},
                    "allowed": [],
                }
            ]
        )

        results = list(monitor.audit())
        assert len(results) == 0

    def test_audit_scope_match(self, monitor, mock_scope, mock_protocol_mapper):
        mock_scope.get_protocol_mappers.return_value = [mock_protocol_mapper]
        monitor._DB.get_all_scopes.return_value = [mock_scope]
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
        assert results[0].to_dict()["entity"] == mock_scope.get_name()

    def test_audit_allowed_scope(self, monitor, mock_scope, mock_protocol_mapper):
        mock_scope.get_protocol_mappers.return_value = [mock_protocol_mapper]
        monitor._DB.get_all_scopes.return_value = [mock_scope]
        monitor.get_custom_config = Mock(
            return_value=[
                {
                    "protocol-mapper-type": "oidc-usermodel-attribute-mapper",
                    "matched-config": {"userinfo.token.claim": "true"},
                    "allowed": [mock_scope.get_name()],
                }
            ]
        )

        results = list(monitor.audit())
        assert len(results) == 0

    def test_audit_multiple_scopes(self, monitor, mock_scope, create_mock_scope, mock_protocol_mapper):
        other_scope = create_mock_scope(name="other-scope")
        mock_scope.get_protocol_mappers.return_value = [mock_protocol_mapper]
        other_scope.get_protocol_mappers.return_value = [mock_protocol_mapper]
        monitor._DB.get_all_scopes.return_value = [mock_scope, other_scope]
        monitor.get_custom_config = Mock(
            return_value=[
                {
                    "protocol-mapper-type": "oidc-usermodel-attribute-mapper",
                    "matched-config": {},
                    "allowed": [],
                }
            ]
        )

        results = list(monitor.audit())
        assert len(results) == 2

    def test_audit_multiple_configs(self, monitor, mock_scope, mock_protocol_mapper):
        mock_scope.get_protocol_mappers.return_value = [mock_protocol_mapper]
        monitor._DB.get_all_scopes.return_value = [mock_scope]
        monitor.get_custom_config = Mock(
            return_value=[
                {
                    "protocol-mapper-type": "oidc-usermodel-attribute-mapper",
                    "matched-config": {"userinfo.token.claim": "true"},
                    "allowed": [],
                },
                {
                    "protocol-mapper-type": "oidc-audience-mapper",
                    "matched-config": {},
                    "allowed": [],
                },
            ]
        )

        results = list(monitor.audit())
        # Only the first config matches the mock mapper type
        assert len(results) == 1
        assert results[0].to_dict()["entity"] == mock_scope.get_name()

    def test_audit_skips_default_template_entry(self, monitor, mock_scope, mock_protocol_mapper):
        mock_scope.get_protocol_mappers.return_value = [mock_protocol_mapper]
        monitor._DB.get_all_scopes.return_value = [mock_scope]
        monitor.get_custom_config = Mock(
            return_value=[
                {
                    "protocol-mapper-type": "mapper name or regular expression",
                    "matched-config": {},
                    "allowed": [],
                }
            ]
        )

        results = list(monitor.audit())
        assert len(results) == 0
