from unittest.mock import patch

import pytest

from kcwarden.auditors.realm.password_policy_missing import PasswordPolicyMissing
from kcwarden.custom_types.keycloak_object import Realm


class TestPasswordPolicyMissing:
    @pytest.fixture
    def auditor(self, mock_database, default_config):
        return PasswordPolicyMissing(mock_database, default_config)

    def test_should_consider_realm(self, auditor, mock_realm: Realm):
        assert auditor.should_consider_realm(mock_realm) is True  # Always consider unless specifically ignored

    def test_password_policy_empty(self, auditor, mock_realm: Realm):
        # Test with no password policy set
        mock_realm.get_password_policy.return_value = ""
        assert auditor.realm_has_no_password_policy(mock_realm)

    def test_password_policy_set(self, auditor, mock_realm: Realm):
        # Test with some password policy set
        mock_realm.get_password_policy.return_value = "length(15)"
        assert not auditor.realm_has_no_password_policy(mock_realm)
