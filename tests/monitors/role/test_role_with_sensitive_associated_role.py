import pytest
from unittest.mock import Mock

from kcwarden.monitors.role.role_with_sensitive_associated_role import RoleWithSensitiveAssociatedRole


class TestRoleWithSensitiveAssociatedRole:
    @pytest.fixture
    def monitor(self, database, default_config):
        return RoleWithSensitiveAssociatedRole(database, default_config)

    def test_audit_composite_realm_role_contains_sensitive_role(self, monitor, mock_database, create_mock_role):
        sensitive_role = create_mock_role("sensitive-role")
        composite_role = create_mock_role("composite-role", composite=[sensitive_role])
        monitor._DB = mock_database
        monitor._DB.get_all_realm_roles.return_value = [sensitive_role, composite_role]
        monitor._DB.get_all_client_roles.return_value = {}
        monitor.get_custom_config = Mock(
            return_value=[
                {
                    "role": sensitive_role.get_name(),
                    "role-client": "realm",
                    "allowed": [],
                }
            ]
        )

        results = list(monitor.audit())
        assert len(results) == 1
        assert results[0].to_dict()["entity"] == composite_role.get_name()

    def test_audit_no_finding_when_container_role_is_allowed(self, monitor, mock_database, create_mock_role):
        sensitive_role = create_mock_role("sensitive-role")
        composite_role = create_mock_role("composite-role", composite=[sensitive_role])
        monitor._DB = mock_database
        monitor._DB.get_all_realm_roles.return_value = [sensitive_role, composite_role]
        monitor._DB.get_all_client_roles.return_value = {}
        monitor.get_custom_config = Mock(
            return_value=[
                {
                    "role": sensitive_role.get_name(),
                    "role-client": "realm",
                    "allowed": [composite_role.get_name()],
                }
            ]
        )

        results = list(monitor.audit())
        assert len(results) == 0

    def test_audit_no_finding_when_no_composite_roles_exist(self, monitor, mock_database, create_mock_role):
        sensitive_role = create_mock_role("sensitive-role")
        monitor._DB = mock_database
        monitor._DB.get_all_realm_roles.return_value = [sensitive_role]
        monitor._DB.get_all_client_roles.return_value = {}
        monitor.get_custom_config = Mock(
            return_value=[
                {
                    "role": sensitive_role.get_name(),
                    "role-client": "realm",
                    "allowed": [],
                }
            ]
        )

        results = list(monitor.audit())
        assert len(results) == 0

    def test_audit_client_role_contains_sensitive_role(self, monitor, mock_database, create_mock_role):
        sensitive_role = create_mock_role("sensitive-role", "some-client")
        composite_role = create_mock_role("composite-role", "some-client", composite=[sensitive_role])
        monitor._DB = mock_database
        monitor._DB.get_all_realm_roles.return_value = []
        monitor._DB.get_all_client_roles.return_value = {
            "some-client": {
                sensitive_role.get_name(): sensitive_role,
                composite_role.get_name(): composite_role,
            }
        }
        monitor.get_custom_config = Mock(
            return_value=[
                {
                    "role": sensitive_role.get_name(),
                    "role-client": "some-client",
                    "allowed": [],
                }
            ]
        )

        results = list(monitor.audit())
        assert len(results) == 1
        assert results[0].to_dict()["entity"] == composite_role.get_name()

    def test_audit_transitive_composite_role(self, monitor, mock_database, create_mock_role):
        # sensitive-role <- intermediate-role <- outer-role
        sensitive_role = create_mock_role("sensitive-role")
        intermediate_role = create_mock_role("intermediate-role", composite=[sensitive_role])
        outer_role = create_mock_role("outer-role", composite=[intermediate_role])
        monitor._DB = mock_database
        monitor._DB.get_all_realm_roles.return_value = [sensitive_role, intermediate_role, outer_role]
        monitor._DB.get_all_client_roles.return_value = {}
        monitor.get_custom_config = Mock(
            return_value=[
                {
                    "role": sensitive_role.get_name(),
                    "role-client": "realm",
                    "allowed": [],
                }
            ]
        )

        results = list(monitor.audit())
        # Both intermediate-role and outer-role should be flagged
        assert len(results) == 2
        reported_names = {r.to_dict()["entity"] for r in results}
        assert intermediate_role.get_name() in reported_names
        assert outer_role.get_name() in reported_names

    def test_audit_regex_role_name(self, monitor, mock_database, create_mock_role):
        sensitive_role1 = create_mock_role("sensitive-role-1")
        sensitive_role2 = create_mock_role("sensitive-role-2")
        composite_role1 = create_mock_role("composite-role-1", composite=[sensitive_role1])
        composite_role2 = create_mock_role("composite-role-2", composite=[sensitive_role2])
        monitor._DB = mock_database
        monitor._DB.get_all_realm_roles.return_value = [
            sensitive_role1,
            sensitive_role2,
            composite_role1,
            composite_role2,
        ]
        monitor._DB.get_all_client_roles.return_value = {}
        monitor.get_custom_config = Mock(
            return_value=[
                {
                    "role": "sensitive-role-.*",
                    "role-client": "realm",
                    "allowed": [],
                }
            ]
        )

        results = list(monitor.audit())
        assert len(results) == 2

    def test_audit_multiple_monitor_definitions(self, monitor, mock_database, create_mock_role):
        sensitive_role1 = create_mock_role("sensitive-role-1")
        sensitive_role2 = create_mock_role("sensitive-role-2")
        composite_role1 = create_mock_role("composite-role-1", composite=[sensitive_role1])
        composite_role2 = create_mock_role("composite-role-2", composite=[sensitive_role2])
        monitor._DB = mock_database
        monitor._DB.get_all_realm_roles.return_value = [
            sensitive_role1,
            sensitive_role2,
            composite_role1,
            composite_role2,
        ]
        monitor._DB.get_all_client_roles.return_value = {}
        monitor.get_custom_config = Mock(
            return_value=[
                {
                    "role": sensitive_role1.get_name(),
                    "role-client": "realm",
                    "allowed": [],
                },
                {
                    "role": sensitive_role2.get_name(),
                    "role-client": "realm",
                    "allowed": [],
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
                    "role": RoleWithSensitiveAssociatedRole.CUSTOM_CONFIG_TEMPLATE["role"],
                    "role-client": "realm",
                    "allowed": [],
                }
            ]
        )

        results = list(monitor.audit())
        assert len(results) == 0
