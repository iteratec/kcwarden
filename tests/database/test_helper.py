from kcwarden.database.helper import (
    _role_contains_role,
    get_effective_roles_for_service_account_direct_assignments,
    get_effective_roles_for_service_account_group_assignments,
    get_effective_roles_for_service_account,
)
from kcwarden.custom_types.keycloak_object import Realm, RealmRole, ClientRole, Group, ServiceAccount
import pytest


# Module-level helpers for constructing keycloak objects used in service account role tests.
# These are plain functions (not fixtures) since each test needs objects with different parameters.


def make_realm_role(name, realm, composite=False, composites=None):
    data = {
        "id": f"id-{name}",
        "name": name,
        "composite": composite,
        "clientRole": False,
        "containerId": "container-id",
        "attributes": {},
    }
    if composites:
        data["composites"] = composites
    return RealmRole(data, realm)


def make_client_role(name, client_name, realm, composite=False, composites=None):
    data = {
        "id": f"id-{name}",
        "name": name,
        "composite": composite,
        "clientRole": True,
        "containerId": "container-id",
        "attributes": {},
    }
    if composites:
        data["composites"] = composites
    return ClientRole(data, realm, client_name)


def make_service_account(realm, realm_roles=None, client_roles=None, groups=None):
    return ServiceAccount(
        {
            "username": "test-service-account",
            "serviceAccountClientId": "test-client",
            "realmRoles": realm_roles or [],
            "clientRoles": client_roles or {},
            "groups": groups or [],
        },
        realm,
    )


def make_group(name, path, realm, realm_roles=None, client_roles=None):
    return Group(
        {
            "id": f"id-{name}",
            "name": name,
            "path": path,
            "attributes": {},
            "realmRoles": realm_roles or [],
            "clientRoles": client_roles or {},
            "subGroups": [],
        },
        realm,
    )


@pytest.fixture
def realm(realm_json):
    return Realm(realm_json)


class TestRoleContainsRole:
    @staticmethod
    def wrap_role(wrapper_role_json, wrapped_role_json, wrapped_role_client=None):
        assert wrapper_role_json["composite"], "Must pass a composite role JSON as parameter"
        if wrapped_role_client:
            wrapper_role_json["composites"] = {"client": {wrapped_role_client: [wrapped_role_json["name"]]}}
        else:
            wrapper_role_json["composites"] = {"realm": [wrapped_role_json["name"]]}
        return wrapper_role_json, wrapped_role_json

    @pytest.fixture
    def wrapped_client_role(self, composite_realm_role_json, client_role_json, realm_json):
        client_name = "client-role-client"
        realm = Realm(realm_json)
        wrapper, wrapped = self.wrap_role(composite_realm_role_json, client_role_json, client_name)
        print(wrapper, wrapped)
        return RealmRole(wrapper, realm), ClientRole(wrapped, realm, client_name)

    @pytest.fixture
    def wrapped_realm_role(self, composite_realm_role_json, realm_role_json, realm_json):
        realm = Realm(realm_json)
        wrapper, wrapped = self.wrap_role(composite_realm_role_json, realm_role_json)
        return RealmRole(wrapper, realm), RealmRole(wrapped, realm)

    def test_role_contains_role_client_role_in_comp(self, wrapped_client_role):
        wrapper_role, wrapped_role = wrapped_client_role
        assert _role_contains_role(wrapped_role, wrapper_role)

    def test_role_contains_role_realm_role_in_comp(self, wrapped_realm_role):
        wrapper_role, wrapped_role = wrapped_realm_role
        assert _role_contains_role(wrapped_role, wrapper_role)

    def test_role_contains_role_container_role_is_no_composite_role(
        self, realm_role_json, client_role_json, realm_json
    ):
        realm = Realm(realm_json)
        role1 = RealmRole(realm_role_json, realm)
        role2 = ClientRole(client_role_json, realm, "client")
        assert not _role_contains_role(role1, role2)

    def test_role_contains_role_container_role_is_composite_but_does_not_contain_role(
        self, client_role_json, composite_realm_role_json, realm_json
    ):
        realm = Realm(realm_json)
        role1 = ClientRole(client_role_json, realm, "client")
        role2 = RealmRole(composite_realm_role_json, realm)
        assert role2.is_composite_role()
        assert not _role_contains_role(role1, role2)


class TestGetEffectiveRolesForServiceAccountDirectAssignments:
    def test_returns_empty_dict_when_no_roles(self, database, realm):
        sa = make_service_account(realm)
        database.add_service_account(sa)
        result = get_effective_roles_for_service_account_direct_assignments(database, sa)
        assert result == {"realm": [], "client": {}}

    def test_returns_single_realm_role(self, database, realm):
        database.add_realm_role(make_realm_role("my-role", realm))
        sa = make_service_account(realm, realm_roles=["my-role"])
        database.add_service_account(sa)
        result = get_effective_roles_for_service_account_direct_assignments(database, sa)
        assert sorted(result["realm"]) == ["my-role"]
        assert result["client"] == {}

    def test_returns_single_client_role(self, database, realm):
        database.add_client_role(make_client_role("my-client-role", "my-client", realm))
        sa = make_service_account(realm, client_roles={"my-client": ["my-client-role"]})
        database.add_service_account(sa)
        result = get_effective_roles_for_service_account_direct_assignments(database, sa)
        assert result["realm"] == []
        assert sorted(result["client"].get("my-client", [])) == ["my-client-role"]

    def test_expands_composite_realm_role(self, database, realm):
        database.add_realm_role(make_realm_role("child-role", realm))
        database.add_realm_role(
            make_realm_role("composite-role", realm, composite=True, composites={"realm": ["child-role"]})
        )
        sa = make_service_account(realm, realm_roles=["composite-role"])
        database.add_service_account(sa)
        result = get_effective_roles_for_service_account_direct_assignments(database, sa)
        assert "composite-role" in result["realm"]
        assert "child-role" in result["realm"]

    def test_returns_multiple_realm_roles(self, database, realm):
        database.add_realm_role(make_realm_role("role-1", realm))
        database.add_realm_role(make_realm_role("role-2", realm))
        sa = make_service_account(realm, realm_roles=["role-1", "role-2"])
        database.add_service_account(sa)
        result = get_effective_roles_for_service_account_direct_assignments(database, sa)
        assert sorted(result["realm"]) == ["role-1", "role-2"]

    def test_returns_both_realm_and_client_roles(self, database, realm):
        database.add_realm_role(make_realm_role("realm-role", realm))
        database.add_client_role(make_client_role("client-role", "my-client", realm))
        sa = make_service_account(realm, realm_roles=["realm-role"], client_roles={"my-client": ["client-role"]})
        database.add_service_account(sa)
        result = get_effective_roles_for_service_account_direct_assignments(database, sa)
        assert "realm-role" in result["realm"]
        assert "client-role" in result["client"]["my-client"]


class TestGetEffectiveRolesForServiceAccountGroupAssignments:
    def test_returns_empty_dict_when_no_groups_in_db(self, database, realm):
        sa = make_service_account(realm)
        database.add_service_account(sa)
        result = get_effective_roles_for_service_account_group_assignments(database, sa)
        assert result == {"realm": [], "client": {}}

    def test_returns_realm_role_from_assigned_group(self, database, realm):
        database.add_realm_role(make_realm_role("group-realm-role", realm))
        database.add_group(make_group("test-group", "/test-group", realm, realm_roles=["group-realm-role"]))
        sa = make_service_account(realm, groups=["/test-group"])
        database.add_service_account(sa)
        result = get_effective_roles_for_service_account_group_assignments(database, sa)
        assert "group-realm-role" in result["realm"]

    def test_returns_client_role_from_assigned_group(self, database, realm):
        database.add_client_role(make_client_role("group-client-role", "my-client", realm))
        database.add_group(
            make_group("test-group", "/test-group", realm, client_roles={"my-client": ["group-client-role"]})
        )
        sa = make_service_account(realm, groups=["/test-group"])
        database.add_service_account(sa)
        result = get_effective_roles_for_service_account_group_assignments(database, sa)
        assert "group-client-role" in result["client"]["my-client"]

    def test_excludes_roles_from_group_sa_does_not_belong_to(self, database, realm):
        database.add_realm_role(make_realm_role("other-group-role", realm))
        database.add_group(make_group("other-group", "/other-group", realm, realm_roles=["other-group-role"]))
        sa = make_service_account(realm, groups=[])
        database.add_service_account(sa)
        result = get_effective_roles_for_service_account_group_assignments(database, sa)
        assert "other-group-role" not in result["realm"]

    def test_includes_roles_from_all_assigned_groups(self, database, realm):
        database.add_realm_role(make_realm_role("role-from-group-1", realm))
        database.add_realm_role(make_realm_role("role-from-group-2", realm))
        database.add_group(make_group("group-1", "/group-1", realm, realm_roles=["role-from-group-1"]))
        database.add_group(make_group("group-2", "/group-2", realm, realm_roles=["role-from-group-2"]))
        sa = make_service_account(realm, groups=["/group-1", "/group-2"])
        database.add_service_account(sa)
        result = get_effective_roles_for_service_account_group_assignments(database, sa)
        assert "role-from-group-1" in result["realm"]
        assert "role-from-group-2" in result["realm"]


class TestGetEffectiveRolesForServiceAccount:
    def test_returns_direct_realm_role(self, database, realm):
        database.add_realm_role(make_realm_role("direct-role", realm))
        sa = make_service_account(realm, realm_roles=["direct-role"])
        database.add_service_account(sa)
        result = get_effective_roles_for_service_account(database, sa)
        assert "direct-role" in result["realm"]

    def test_returns_group_realm_role(self, database, realm):
        database.add_realm_role(make_realm_role("group-role", realm))
        database.add_group(make_group("test-group", "/test-group", realm, realm_roles=["group-role"]))
        sa = make_service_account(realm, groups=["/test-group"])
        database.add_service_account(sa)
        result = get_effective_roles_for_service_account(database, sa)
        assert "group-role" in result["realm"]

    def test_combines_direct_and_group_roles(self, database, realm):
        database.add_realm_role(make_realm_role("direct-role", realm))
        database.add_realm_role(make_realm_role("group-role", realm))
        database.add_group(make_group("test-group", "/test-group", realm, realm_roles=["group-role"]))
        sa = make_service_account(realm, realm_roles=["direct-role"], groups=["/test-group"])
        database.add_service_account(sa)
        result = get_effective_roles_for_service_account(database, sa)
        assert "direct-role" in result["realm"]
        assert "group-role" in result["realm"]

    def test_deduplicates_role_assigned_directly_and_via_group(self, database, realm):
        database.add_realm_role(make_realm_role("shared-role", realm))
        database.add_group(make_group("test-group", "/test-group", realm, realm_roles=["shared-role"]))
        sa = make_service_account(realm, realm_roles=["shared-role"], groups=["/test-group"])
        database.add_service_account(sa)
        result = get_effective_roles_for_service_account(database, sa)
        assert result["realm"].count("shared-role") == 1
