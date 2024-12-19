import pytest
from unittest.mock import Mock

from kcwarden.monitors.group.group_with_sensitive_role import GroupWithSensitiveRole


class TestGroupWithSensitiveRole:
    @pytest.fixture
    def monitor(self, database, default_config):
        return GroupWithSensitiveRole(database, default_config)

    def test_audit(self, monitor, mock_group, mock_database, create_mock_role):
        mock_role = create_mock_role("sensitive-role")
        monitor._DB = mock_database
        monitor._DB.get_all_realm_roles.return_value = [mock_role]
        mock_group.get_effective_realm_roles.return_value = [mock_role.get_name()]
        monitor._DB.get_all_groups.return_value = [mock_group]
        monitor.get_custom_config = Mock(
            return_value=[
                {
                    "role": mock_role.get_name(),
                    "role-client": "realm",
                    "allowed": ["/allowed-group"],
                }
            ]
        )

        results = list(monitor.audit())
        assert len(results) == 1
        assert results[0].to_dict()["entity"] == mock_group.get_name()

    def test_audit_client_role(self, monitor, mock_group, mock_database, create_mock_role):
        mock_role = create_mock_role("sensitive-role", "test-client")
        monitor._DB = mock_database
        monitor._DB.get_all_client_roles.return_value = {"test-client": {mock_role.get_name(): mock_role}}
        mock_group.get_effective_client_roles.return_value = {"test-client": [mock_role.get_name()]}
        monitor._DB.get_all_groups.return_value = [mock_group]
        monitor.get_custom_config = Mock(
            return_value=[
                {
                    "role": mock_role.get_name(),
                    "role-client": mock_role.get_client_name(),
                    "allowed": ["/allowed-group"],
                }
            ]
        )

        results = list(monitor.audit())
        assert len(results) == 1
        assert results[0].to_dict()["entity"] == mock_group.get_name()

    def test_audit_composite_role(self, monitor, mock_group, mock_database, create_mock_role):
        mock_role = create_mock_role("sensitive-role")
        mock_composite = create_mock_role("sensitive-composite-role", composite=[mock_role])
        monitor._DB = mock_database
        monitor._DB.get_all_realm_roles.return_value = [mock_role, mock_composite]
        mock_group.get_effective_realm_roles.return_value = [mock_composite.get_name()]
        monitor._DB.get_all_groups.return_value = [mock_group]
        monitor.get_custom_config = Mock(
            return_value=[
                {
                    "role": mock_role.get_name(),
                    "role-client": "realm",
                    "allowed": ["/allowed-group"],
                }
            ]
        )

        results = list(monitor.audit())
        assert len(results) == 1
        assert results[0].to_dict()["entity"] == mock_group.get_name()

    def test_audit_allowed_group(self, monitor, mock_group, mock_database, create_mock_role):
        mock_role = create_mock_role("sensitive-role")
        monitor._DB = mock_database
        monitor._DB.get_all_realm_roles.return_value = [mock_role]
        mock_group.get_effective_realm_roles.return_value = [mock_role.get_name()]
        mock_group.get_path.return_value = "/allowed-group"
        monitor._DB.get_all_groups.return_value = [mock_group]
        monitor.get_custom_config = Mock(
            return_value=[
                {
                    "role": mock_role.get_name(),
                    "role-client": "realm",
                    "allowed": [mock_group.get_path()],
                }
            ]
        )

        results = list(monitor.audit())
        assert len(results) == 0

    def test_audit_regex_role(self, monitor, mock_group, mock_database, create_mock_role):
        mock_role = create_mock_role("sensitive-role-1")
        mock_role2 = create_mock_role("sensitive-role-2")
        monitor._DB = mock_database
        mock_group.get_effective_realm_roles.return_value = [mock_role.get_name(), mock_role2.get_name()]
        monitor._DB.get_all_realm_roles.return_value = [mock_role, mock_role2]
        monitor._DB.get_all_groups.return_value = [mock_group]
        monitor.get_custom_config = Mock(
            return_value=[
                {
                    "role": "sensitive-role-.*",
                    "role-client": "realm",
                    "allowed": ["/allowed-group"],
                }
            ]
        )
        results = list(monitor.audit())
        assert len(results) == 2

    def test_audit_multiple_configs(self, monitor, mock_group, mock_database, create_mock_role):
        mock_role = create_mock_role("sensitive-role-1")
        mock_role2 = create_mock_role("sensitive-role-2")
        monitor._DB = mock_database
        mock_group.get_effective_realm_roles.return_value = [mock_role.get_name(), mock_role2.get_name()]
        monitor._DB.get_all_groups.return_value = [mock_group]
        monitor._DB.get_all_realm_roles.return_value = [mock_role, mock_role2]
        monitor.get_custom_config = Mock(
            return_value=[
                {
                    "role": mock_role.get_name(),
                    "role-client": "realm",
                    "allowed": ["/allowed-group-1"],
                },
                {
                    "role": mock_role2.get_name(),
                    "role-client": "realm",
                    "allowed": ["/allowed-group-2"],
                },
            ]
        )

        results = list(monitor.audit())
        assert len(results) == 2

    def test_audit_skip_default_config(self, monitor, mock_database):
        monitor._DB = mock_database
        monitor.get_custom_config = Mock(
            return_value=[
                {
                    "role": GroupWithSensitiveRole.CUSTOM_CONFIG_TEMPLATE["role"],
                    "role-client": "realm",
                    "allowed": [],
                }
            ]
        )

        results = list(monitor.audit())
        assert len(results) == 0
