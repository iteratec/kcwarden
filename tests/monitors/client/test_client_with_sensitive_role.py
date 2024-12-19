import pytest

from kcwarden.monitors.client.client_with_sensitive_role import ClientWithSensitiveRole


class TestClientWithSensitiveRole:
    @pytest.fixture
    def monitor(self, mock_database, default_config):
        monitor_instance = ClientWithSensitiveRole(mock_database, default_config)
        return monitor_instance

    @pytest.fixture
    def db_backed_monitor(self, database, default_config):
        monitor_instance = ClientWithSensitiveRole(database, default_config)
        return monitor_instance

    def create_monitor_config(
        self,
        role_name="sensitive-role",
        role_client="realm",
        allowed=[],
        ignore_full_scope_allowed=False,
        ignore_disabled_clients=False,
    ):
        return {
            "ignore_disabled_clients": ignore_disabled_clients,
            "auditors": {},
            "monitors": {
                "ClientWithSensitiveRole": [
                    {
                        "role": role_name,
                        "role-client": role_client,
                        "allowed": allowed,
                        "ignore_full_scope_allowed": ignore_full_scope_allowed,
                    }
                ]
            },
        }

    def prepare_mapper_and_scope(self, db_backed_monitor, mapper_type, create_mock_protocol_mapper, create_mock_scope):
        # Create a mock protocol mapper that should match the requirements
        mock_protocol_mapper = create_mock_protocol_mapper(mapper_type)
        # Create a scope and attach the protocol mapper
        mock_scope = create_mock_scope(name="scope-1", protocol_mappers=[mock_protocol_mapper])

        db_backed_monitor._DB.add_scope(mock_scope)

        return mock_scope

    def prepare_scope_with_mapped_role(self, scope_name, role_name, db_backed_monitor, create_mock_scope):
        # Create a scope and attach the protocol mapper
        mock_scope = create_mock_scope(name=scope_name, realm_roles=[role_name])

        db_backed_monitor._DB.add_scope(mock_scope)

        return mock_scope

    # Test _protocol_mapper_is_role_mapper
    @pytest.mark.parametrize(
        "mapper_type, result",
        [
            ("oidc-usermodel-client-role-mapper", True),
            ("oidc-usermodel-realm-role-mapper", True),
            ("oidc-hardcoded-mapper", False),
        ],
    )
    def test_protocol_mapper_is_role_mapper(self, monitor, create_mock_protocol_mapper, mapper_type, result):
        mock_protocol_mapper = create_mock_protocol_mapper(mapper_type)
        assert monitor._protocol_mapper_is_role_mapper(mock_protocol_mapper) == result

    # Test _get_role_mappers_for_client
    def test_get_role_mappers_for_client(self, monitor, create_mock_protocol_mapper, mock_client):
        mock_protocol_mapper = create_mock_protocol_mapper("oidc-usermodel-client-role-mapper")
        mock_client.get_protocol_mappers.return_value = [mock_protocol_mapper]
        matched_mappers = monitor._get_role_mappers_for_client(mock_client)
        assert len(matched_mappers) == 1
        assert mock_protocol_mapper in matched_mappers

    def test_get_role_mappers_for_client_multiple_mappers(self, monitor, create_mock_protocol_mapper, mock_client):
        mock_protocol_mapper = create_mock_protocol_mapper("oidc-usermodel-client-role-mapper")
        second_mock_protocol_mapper = create_mock_protocol_mapper("oidc-usermodel-realm-role-mapper")
        mock_client.get_protocol_mappers.return_value = [mock_protocol_mapper, second_mock_protocol_mapper]
        matched_mappers = monitor._get_role_mappers_for_client(mock_client)
        assert len(matched_mappers) == 2
        assert mock_protocol_mapper in matched_mappers
        assert second_mock_protocol_mapper in matched_mappers

    def test_get_role_mappers_for_client_only_return_matching_mappers(
        self, monitor, create_mock_protocol_mapper, mock_client
    ):
        mock_protocol_mapper = create_mock_protocol_mapper("oidc-usermodel-client-role-mapper")
        second_mock_protocol_mapper = create_mock_protocol_mapper("oidc-constant-mapper")
        mock_client.get_protocol_mappers.return_value = [mock_protocol_mapper, second_mock_protocol_mapper]
        matched_mappers = monitor._get_role_mappers_for_client(mock_client)
        assert len(matched_mappers) == 1
        assert mock_protocol_mapper in matched_mappers

    # Test _get_role_mapping_default_scopes_for_client
    def test_get_role_mapping_default_scopes_for_client(
        self, db_backed_monitor, create_mock_scope, create_mock_protocol_mapper, mock_client
    ):
        mock_scope = self.prepare_mapper_and_scope(
            db_backed_monitor, "oidc-usermodel-client-role-mapper", create_mock_protocol_mapper, create_mock_scope
        )
        mock_client.get_default_client_scopes.return_value = [mock_scope.get_name()]

        matched_scopes = db_backed_monitor._get_role_mapping_default_scopes_for_client(mock_client)
        assert len(matched_scopes) == 1

    # Test _get_role_mapping_optional_scopes_for_client
    def test_get_role_mapping_optional_scopes_for_client(
        self, db_backed_monitor, create_mock_scope, create_mock_protocol_mapper, mock_client
    ):
        mock_scope = self.prepare_mapper_and_scope(
            db_backed_monitor, "oidc-usermodel-client-role-mapper", create_mock_protocol_mapper, create_mock_scope
        )
        mock_client.get_optional_client_scopes.return_value = [mock_scope.get_name()]

        matched_scopes = db_backed_monitor._get_role_mapping_optional_scopes_for_client(mock_client)
        assert len(matched_scopes) == 1

    # Test _client_has_some_way_of_mapping_roles
    def test_client_has_some_way_of_mapping_roles_with_optional_scope(
        self, db_backed_monitor, create_mock_scope, create_mock_protocol_mapper, mock_client
    ):
        mock_scope = self.prepare_mapper_and_scope(
            db_backed_monitor, "oidc-usermodel-client-role-mapper", create_mock_protocol_mapper, create_mock_scope
        )
        mock_client.get_optional_client_scopes.return_value = [mock_scope.get_name()]

        assert db_backed_monitor._client_has_some_way_of_mapping_roles(mock_client)

    def test_client_has_some_way_of_mapping_roles_with_direct_role_mapper(
        self, monitor, create_mock_protocol_mapper, mock_client
    ):
        mock_protocol_mapper = create_mock_protocol_mapper("oidc-usermodel-client-role-mapper")
        second_mock_protocol_mapper = create_mock_protocol_mapper("oidc-usermodel-realm-role-mapper")
        mock_client.get_protocol_mappers.return_value = [mock_protocol_mapper, second_mock_protocol_mapper]

        assert monitor._client_has_some_way_of_mapping_roles(mock_client)

    def test_client_has_some_way_of_mapping_roles_but_not_without_anything(self, monitor, mock_client):
        assert not monitor._client_has_some_way_of_mapping_roles(mock_client)

    # Test audit function
    # We have several cases that we need to test:
    # First, the combinations for the role:
    # - Role directly assigned to the client
    # - Role assigned to a Client Scope
    # - Role part of a larger composite role, assigned to the client
    # - Role part of a larger composite role, assigned to a scope that is assigned to the client
    # - Role not assigned to the client, but full scope allowed enabled
    # - Role not assigned to any scope (no findings)
    # Then, the combinations for the mappers:
    # - Mapper directly assigned to the client
    # - Mapper assigned to a scope which is assigned to the client
    # - Mapper not assigned (no findings)
    # Ideally, all of these combinations should be tested.

    # fmt: off
    @pytest.mark.parametrize(
        "role_direct, role_default_scope, role_optional_scope, role_composite_direct, role_composite_scope, role_full_scope, mapper_direct, mapper_default_scope, mapper_optional_scope, expected_result_count",
        [
            # RD    RDS    ROS    RCD    RCS    RFS  | MD,    MDS,   MOS,  EXP
            # No findings if no way to map the roles is present
            (True , False, False, False, False, False, False, False, False, 0),
            (False, True , False, False, False, False, False, False, False, 0),
            (False, False, True , False, False, False, False, False, False, 0),
            (False, False, False, True , False, False, False, False, False, 0),
            (False, False, False, False, True , False, False, False, False, 0),
            (False, False, False, False, False, True , False, False, False, 0),
            # No findings if no role is present
            (False, False, False, False, False, False, True , False, False, 0),
            (False, False, False, False, False, False, False, True , False, 0),
            (False, False, False, False, False, False, False, False, True , 0),
            # Individual ways of adding the role, only one active at a time, all in combination with a directly-assigned role mapper
            (True , False, False, False, False, False, True , False, False, 1),
            (False, True , False, False, False, False, True , False, False, 1),
            (False, False, True , False, False, False, True , False, False, 1),
            (False, False, False, True , False, False, True , False, False, 1),
            (False, False, False, False, True , False, True , False, False, 1),
            (False, False, False, False, False, True , True , False, False, 1),
            # Combinations of the above
            (False, True , True , False, False, False, True , False, False, 2),  # Both optional and default scope => 2 findings
            (False, True , True , False, False, True , True , False, False, 3),  # Both optional and default scope, plus full scope allowed => 3 findings
            (True , True , True , False, False, True , True , False, False, 4),  # Plus direct assignment => 4 findings

            # Individual ways of adding the role, only one active at a time, all in combination with a default-scope role mapper
            (True , False, False, False, False, False, False, True , False, 1),
            (False, True , False, False, False, False, False, True , False, 1),
            (False, False, True , False, False, False, False, True , False, 1),
            (False, False, False, True , False, False, False, True , False, 1),
            (False, False, False, False, True , False, False, True , False, 1),
            (False, False, False, False, False, True , False, True , False, 1),
            # Combinations of the above
            (False, True , True , False, False, False, False, True , False, 2),  # Both optional and default scope => 2 findings
            (False, True , True , False, False, True , False, True , False, 3),  # Both optional and default scope, plus full scope allowed => 3 findings
            (True , True , True , False, False, True , False, True , False, 4),  # Plus direct assignment => 4 findings
            
            # Individual ways of adding the role, only one active at a time, all in combination with an optional-scope role mapper
            (True , False, False, False, False, False, False, False, True , 1),
            (False, True , False, False, False, False, False, False, True , 1),
            (False, False, True , False, False, False, False, False, True , 1),
            (False, False, False, True , False, False, False, False, True , 1),
            (False, False, False, False, True , False, False, False, True , 1),
            (False, False, False, False, False, True , False, False, True , 1),
            # Combinations of the above
            (False, True , True , False, False, False, False, False, True , 2),  # Both optional and default scope => 2 findings
            (False, True , True , False, False, True , False, False, True , 3),  # Both optional and default scope, plus full scope allowed => 3 findings
            (True , True , True , False, False, True , False, False, True , 4),  # Plus direct assignment => 4 findings

            # Individual ways of adding the role, only one active at a time, all in combination with more than one assigned role mapper
            (True , False, False, False, False, False, True , True , False, 1),  # All of these will only match once, because they don't care about optional vs. default scope vs. direct assignment
            (False, True , False, False, False, False, True , True , False, 1),
            (False, False, True , False, False, False, True , True , False, 1),
            (False, False, False, True , False, False, True , True , False, 1),
            (False, False, False, False, True , False, True , True , False, 1),
            (False, False, False, False, False, True , True , True , False, 2),  # Full Scope Allowed will raise a separate warning
            # Combinations of the above
            (False, True , True , False, False, False, True , True, False, 2),  # Both optional and default scope => 2 findings
            (False, True , True , False, False, True , True , True, False, 4),  # Both optional and default scope, plus full scope allowed => 4 findings (one extra because of behavior above)
            (True , True , True , False, False, True , True , True, False, 5),  # Plus direct assignment => 5 findings (same)
            
            # Individual ways of adding the role, only one active at a time, all in combination with scope and direct mapper
            (True , False, False, False, False, False, True , False, True , 1),  # All of these will only match once, because they don't care about optional vs. default scope vs. direct assignment
            (False, True , False, False, False, False, True , False, True , 1),
            (False, False, True , False, False, False, True , False, True , 1),
            (False, False, False, True , False, False, True , False, True , 1),
            (False, False, False, False, True , False, True , False, True , 1),
            (False, False, False, False, False, True , True , False, True , 2),  # Full Scope Allowed will raise a separate warning
            # Combinations of the above
            (False, True , True , False, False, False, True , False, True , 2),  # Both optional and default scope => 2 findings
            (False, True , True , False, False, True , True , False, True , 4),  # Both optional and default scope, plus full scope allowed => 4 findings (one extra because of behavior above)
            (True , True , True , False, False, True , True , False, True , 5),  # Plus direct assignment => 5 findings (same)
        ]
    )
    # fmt: on
    def test_audit(
        self,
        db_backed_monitor,
        create_mock_scope,
        create_mock_protocol_mapper,
        create_mock_role,
        mock_client, 
        # Additional parameters to control execution of the test case variants
        role_direct,           # Role is assigned directly to the client
        role_default_scope,    # Role is assigned as part of a default scope
        role_optional_scope,   # Role is assigned through an optional scope
        role_composite_direct, # Role is assigned directly to the client through a composite role
        role_composite_scope,  # Role is assigned through a scope through a composite role
        role_full_scope,       # Client has full scope allowed
        mapper_direct,         # Role mapper assigned directly to the client
        mapper_default_scope,  # Role mapper assigned through default scope
        mapper_optional_scope, # Role mapper assigned through optional scope
        expected_result_count  # Number of expected findings
    ):
        def _client_matched_by(reason, findings):
            return reason in [finding._additional_details["matched_by"] for finding in findings]
        
        def _client_matched_scope(scope, findings):
            return scope in [finding._additional_details.get("matched_scope", None) for finding in findings]

        # Initialize config for the monitor
        db_backed_monitor._CONFIG = self.create_monitor_config()

        if mapper_direct or mapper_default_scope or mapper_optional_scope:
        # Prepare a scope that allows the client to map roles
            mock_scope = self.prepare_mapper_and_scope(
                db_backed_monitor, "oidc-usermodel-client-role-mapper", create_mock_protocol_mapper, create_mock_scope
            )
            if mapper_optional_scope:
                mock_client.get_optional_client_scopes.return_value = [mock_scope.get_name()]
            if mapper_default_scope:
                mock_client.get_default_client_scopes.return_value = [mock_scope.get_name()]
            if mapper_direct:
                mock_protocol_mapper = create_mock_protocol_mapper("oidc-usermodel-client-role-mapper")
                mock_client.get_protocol_mappers.return_value = [mock_protocol_mapper]
        if role_full_scope:
            # Set "Full Scope Allowed" on Client
            mock_client.has_full_scope_allowed.return_value = True

        # Prepare a sensitive role
        role = create_mock_role(role_name="sensitive-role")
        db_backed_monitor._DB.add_realm_role(role)
        
        if role_direct:
            # Set the role as directly assigned on the client
            mock_client.get_directly_assigned_realm_roles.return_value = [role.get_name()]
        if role_default_scope:
            scope1 = self.prepare_scope_with_mapped_role("scope-def", role.get_name(), db_backed_monitor, create_mock_scope)
            mock_client.get_default_client_scopes.return_value.append(scope1.get_name())
        if role_optional_scope:
            scope2 = self.prepare_scope_with_mapped_role("scope-opt", role.get_name(), db_backed_monitor, create_mock_scope)
            mock_client.get_optional_client_scopes.return_value.append(scope2.get_name())
        if role_composite_direct or role_composite_scope:
            comp_role = create_mock_role("comp-role", composite=[role])
            db_backed_monitor._DB.add_realm_role(comp_role)
            if role_composite_direct:
                mock_client.get_directly_assigned_realm_roles.return_value = [comp_role.get_name()]
            if role_composite_scope:
                scope3 = self.prepare_scope_with_mapped_role("scope-cmp", comp_role.get_name(), db_backed_monitor, create_mock_scope)
                mock_client.get_optional_client_scopes.return_value.append(scope3.get_name())


        db_backed_monitor._DB.add_client(mock_client)

        findings = list(db_backed_monitor.audit())
        assert len(findings) == expected_result_count

        has_assigned_mapper = any([mapper_direct, mapper_default_scope, mapper_optional_scope])
        if role_direct and has_assigned_mapper:
            assert _client_matched_by("RoleAssignmentToClient", findings)
        if (role_default_scope or role_optional_scope) and has_assigned_mapper:
            assert _client_matched_by("clientScope", findings)
        if role_composite_direct and has_assigned_mapper:
            assert _client_matched_by("RoleAssignmentToClient", findings)
        if role_composite_scope and has_assigned_mapper:
            assert _client_matched_by("clientScope", findings)
            assert _client_matched_scope("scope-cmp", findings)
        if role_full_scope and has_assigned_mapper:
            if mapper_direct:
                assert _client_matched_by("full_scope_allowed_and_directly_assigned_role_mapper", findings)
            if mapper_default_scope:
                assert _client_matched_by("full_scope_allowed_and_default_scope_with_role_mapper", findings)
            if mapper_optional_scope:
                assert _client_matched_by("full_scope_allowed_and_optional_scope_with_role_mapper", findings)
