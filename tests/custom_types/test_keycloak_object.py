from unittest.mock import Mock

import pytest
from unittest.mock import Mock, patch

from kcwarden.custom_types.keycloak_object import Client, Realm


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
