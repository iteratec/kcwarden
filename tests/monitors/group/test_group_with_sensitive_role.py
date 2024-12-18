import pytest
from unittest.mock import Mock

from kcwarden.monitors.group.group_with_sensitive_role import GroupWithSensitiveRole
from kcwarden.custom_types.keycloak_object import RealmRole, ClientRole


class TestGroupWithSensitiveRole:
    @pytest.fixture
    def monitor(self, database, default_config):
        return GroupWithSensitiveRole(database, default_config)

    @pytest.fixture
    def mock_group(self, mock_realm):
        group = Mock()
        group.get_path.return_value = "/test-group"
        group.get_name.return_value = "test-group"
        group.get_realm_roles.return_value = []
        group.get_client_roles.return_value = {}
        group.get_effective_realm_roles.return_value = []
        group.get_effective_client_roles.return_value = {}
        group.get_realm.return_value = mock_realm
        return group

    @pytest.fixture
    def create_mock_role(self, mock_realm):
        # Fixture factory pattern, so we can create more than one role in our tests
        def _create_mock_role(role_name, client="realm", composite=[]):
            if client == "realm":
                role = Mock(spec=RealmRole)
                role.is_client_role.return_value = False
            else:
                role = Mock(spec=ClientRole)
                role.is_client_role.return_value = True
                role.get_client_name.return_value = client
            if len(composite) > 0:
                role.is_composite_role.return_value = True
                comp_map = {}
                for c_role in composite:
                    if c_role.is_client_role():
                        if c_role.get_client_name() not in comp_map:
                            comp_map[c_role.get_client_name()] = []
                        comp_map[c_role.get_client_name()].append(c_role.get_name())
                    else:
                        if "realm" not in comp_map:
                            comp_map["realm"] = []
                        comp_map["realm"].append(c_role.get_name())
                role.get_composite_roles.return_value = comp_map
            else:
                role.is_composite_role.return_value = False
                role.get_composite_roles.return_value = {}
            role.get_name.return_value = role_name
            role.get_realm.return_value = mock_realm
            return role

        return _create_mock_role

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
