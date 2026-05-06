from unittest.mock import Mock

import pytest

from kcwarden.custom_types.keycloak_object import Client, Group, Realm


class TestClient:
    @pytest.mark.parametrize(
        ["attributes", "expected"],
        [
            ({}, True),
            ({"use.refresh.tokens": "true"}, True),
            ({"use.refresh.tokens": "false"}, False),
        ],
    )
    def test_use_refresh_tokens(self, attributes: dict, expected: bool):
        client = Client(
            {
                "clientId": "TEST_CLIENT_ID",
                "attributes": attributes,
            },
            [],
            {},
            realm=Mock(),
        )
        assert client.use_refresh_tokens() == expected

    @pytest.mark.parametrize(
        ["client_id", "expected"],
        [
            ("_system", True),
            ("some-other-client", False),
        ],
    )
    def test_is_system_client(self, client_id: str, expected: bool):
        client = Client(
            {
                "clientId": client_id,
                "attributes": {},
            },
            [],
            {},
            realm=Mock(),
        )
        assert client.is_system_client() == expected

    def test_get_protocol_returns_openid_connect_for_system_client(self):
        client = Client(
            {
                "clientId": "_system",
                "attributes": {},
            },
            [],
            {},
            realm=Mock(),
        )
        assert client.get_protocol() == "openid-connect"

    def test_get_client_authenticator_type_returns_none_for_system_client(self):
        client = Client(
            {
                "clientId": "_system",
                "attributes": {},
            },
            [],
            {},
            realm=Mock(),
        )
        assert client.get_client_authenticator_type() is None


class TestRealm:
    def test_extract_password_policy_empty(self):
        # Test with no password policy
        realm = Realm({})
        assert realm._interpret_password_policy() == {}

    def test_extract_password_policy(self):
        # Test with a password policy string
        realm = Realm({"passwordPolicy": "hashAlgorithm(pbkdf2-sha256) and hashIterations(300000)"})
        expected = {"hashAlgorithm": "pbkdf2-sha256", "hashIterations": "300000"}
        result = realm._interpret_password_policy()
        assert result == expected

    def test_get_hashing_algorithm_from_policy(self):
        # Test getting algorithm from password policy
        realm = Realm({"passwordPolicy": "hashAlgorithm(pbkdf2-sha256) and hashIterations(300000)"})
        assert realm.get_password_hash_algorithm() == "pbkdf2-sha256"

    def test_get_hashing_algorithm_from_realm(self):
        # Test getting algorithm from realm config
        realm = Realm({"passwordHashAlgorithm": "pbkdf2-sha512"})
        assert realm.get_password_hash_algorithm() == "pbkdf2-sha512"

    def test_get_hashing_algorithm_default(self):
        # Test default algorithm when none specified
        realm = Realm({})
        assert realm.get_password_hash_algorithm() == "pbkdf2"

    def test_get_hashing_iterations_from_policy(self):
        # Test getting iterations from password policy
        realm = Realm({"passwordPolicy": "hashAlgorithm(pbkdf2-sha256) and hashIterations(300000)"})
        assert realm.get_password_hash_iterations() == 300000

    def test_get_hashing_iterations_from_realm(self):
        # Test getting iterations from password policy
        realm = Realm({"passwordHashIterations": "300000"})
        assert realm.get_password_hash_iterations() == 300000

    def test_get_hashing_iterations_is_none(self):
        # Test getting iterations from password policy
        realm = Realm({})
        assert realm.get_password_hash_iterations() is None


class TestGroup:
    def test_get_effective_client_roles_does_not_mutate_intermediate_group(self):
        realm = Mock()
        grandparent_raw = {
            "name": "grandparent",
            "path": "/grandparent",
            "attributes": {},
            "realmRoles": [],
            "clientRoles": {"client-a": ["gp-role"]},
            "subGroups": [],
        }
        parent_raw = {
            "name": "parent",
            "path": "/grandparent/parent",
            "attributes": {},
            "realmRoles": [],
            "clientRoles": {"client-b": ["parent-role"]},
            "subGroups": [],
        }
        child_raw = {
            "name": "child",
            "path": "/grandparent/parent/child",
            "attributes": {},
            "realmRoles": [],
            "clientRoles": {"client-b": ["child-role"]},
            "subGroups": [],
        }

        grandparent_group = Group(grandparent_raw, realm)
        parent_group = Group(parent_raw, realm, grandparent_group)
        child_group = Group(child_raw, realm, parent_group)

        effective_roles = child_group.get_effective_client_roles()

        assert effective_roles == {
            "client-a": ["gp-role"],
            "client-b": ["parent-role", "child-role"],
        }
        assert parent_raw["clientRoles"] == {"client-b": ["parent-role"]}

    def test_get_effective_client_roles_does_not_mutate_source_groups(self):
        realm = Mock()
        parent_raw = {
            "name": "parent",
            "path": "/parent",
            "attributes": {},
            "realmRoles": [],
            "clientRoles": {"client-a": ["role-parent"]},
            "subGroups": [],
        }
        child_raw = {
            "name": "child",
            "path": "/parent/child",
            "attributes": {},
            "realmRoles": [],
            "clientRoles": {"client-a": ["role-child"], "client-b": ["role-child-only"]},
            "subGroups": [],
        }

        parent_group = Group(parent_raw, realm)
        child_group = Group(child_raw, realm, parent_group)

        effective_roles = child_group.get_effective_client_roles()

        assert effective_roles == {
            "client-a": ["role-parent", "role-child"],
            "client-b": ["role-child-only"],
        }
        assert parent_raw["clientRoles"] == {"client-a": ["role-parent"]}
        assert child_raw["clientRoles"] == {
            "client-a": ["role-child"],
            "client-b": ["role-child-only"],
        }

    def test_get_effective_client_roles_is_stable_across_calls(self):
        realm = Mock()
        parent_group = Group(
            {
                "name": "parent",
                "path": "/parent",
                "attributes": {},
                "realmRoles": [],
                "clientRoles": {"client-a": ["role-parent"]},
                "subGroups": [],
            },
            realm,
        )
        child_group = Group(
            {
                "name": "child",
                "path": "/parent/child",
                "attributes": {},
                "realmRoles": [],
                "clientRoles": {"client-a": ["role-child"]},
                "subGroups": [],
            },
            realm,
            parent_group,
        )

        first_result = child_group.get_effective_client_roles()
        second_result = child_group.get_effective_client_roles()

        assert first_result == second_result == {"client-a": ["role-parent", "role-child"]}
