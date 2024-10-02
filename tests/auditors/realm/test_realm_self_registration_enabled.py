import pytest
from unittest.mock import Mock

from kcwarden.auditors.realm.realm_self_registration_enabled import RealmSelfRegistrationEnabled


class TestRealmSelfRegistrationEnabled:
    @pytest.fixture
    def auditor(self, mock_database, default_config):
        return RealmSelfRegistrationEnabled(mock_database, default_config)

    def test_should_consider_realm(self, mock_realm, auditor):
        assert auditor.should_consider_realm(mock_realm) is True  # Always consider unless specifically ignored

    @pytest.mark.parametrize(
        "self_registration_enabled, expected",
        [
            (True, True),  # Self-registration enabled
            (False, False),  # Self-registration disabled
        ],
    )
    def test_realm_has_self_registration_enabled(self, auditor, self_registration_enabled, expected, mock_realm):
        mock_realm.is_self_registration_enabled.return_value = self_registration_enabled
        assert auditor.realm_has_self_registration_enabled(mock_realm) == expected

    def test_audit_function_no_findings(self, auditor, mock_realm):
        # Setup realm with self-registration disabled
        mock_realm.is_self_registration_enabled.return_value = False
        auditor._DB.get_all_realms.return_value = [mock_realm]

        results = list(auditor.audit())
        assert len(results) == 0

    def test_audit_function_with_findings(self, auditor, mock_realm):
        # Setup realm with self-registration enabled
        mock_realm.is_self_registration_enabled.return_value = True
        auditor._DB.get_all_realms.return_value = [mock_realm]

        results = list(auditor.audit())
        assert len(results) == 1

    def test_audit_function_multiple_realms(self, auditor):
        # Create separate mock realms with distinct settings
        realm1 = Mock()
        realm1.is_self_registration_enabled.return_value = True

        realm2 = Mock()
        realm2.is_self_registration_enabled.return_value = False

        realm3 = Mock()
        realm3.is_self_registration_enabled.return_value = True

        auditor._DB.get_all_realms.return_value = [realm1, realm2, realm3]
        results = list(auditor.audit())
        assert len(results) == 2  # Expect findings from realm1 and realm3, but not from realm2
