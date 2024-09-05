from kcwarden.database.helper import _role_contains_role
from kcwarden.custom_types.keycloak_object import Realm, RealmRole, ClientRole
import pytest


class TestRoleContainsRole:
    def wrap_role(self, wrapper_role_json, wrapped_role_json, wrapped_role_client=None):
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
