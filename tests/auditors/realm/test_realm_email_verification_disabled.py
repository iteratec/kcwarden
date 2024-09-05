import pytest
from unittest.mock import Mock

from kcwarden.auditors.realm.realm_email_verification_disabled import RealmEmailVerificationDisabled


class TestRealmEmailVerificationDisabled:
    @pytest.fixture
    def auditor(self, database, default_config):
        auditor_instance = RealmEmailVerificationDisabled(database, default_config)
        auditor_instance._DB = Mock()
        return auditor_instance

    def test_should_consider_realm(self, mock_realm, auditor):
        assert auditor.should_consider_realm(mock_realm) is True  # Always consider unless specifically ignored

    @pytest.mark.parametrize(
        "is_verify_email_enabled, expected",
        [
            (True, False),  # Email verification enabled
            (False, True),  # Email verification disabled
        ],
    )
    def test_realm_has_email_verification_disabled(self, auditor, is_verify_email_enabled, expected, mock_realm):
        mock_realm.is_verify_email_enabled.return_value = is_verify_email_enabled
        assert auditor.realm_has_email_verification_disabled(mock_realm) == expected

    def test_audit_function_no_findings(self, auditor, mock_realm):
        # Setup realm with email verification enabled
        mock_realm.is_verify_email_enabled.return_value = True
        auditor._DB.get_all_realms.return_value = [mock_realm]

        results = list(auditor.audit())
        assert len(results) == 0

    def test_audit_function_with_findings(self, auditor, mock_realm):
        # Setup realm with email verification disabled
        mock_realm.is_verify_email_enabled.return_value = False
        auditor._DB.get_all_realms.return_value = [mock_realm]

        results = list(auditor.audit())
        assert len(results) == 1

    def test_audit_function_multiple_realms(self, auditor):
        # Create separate mock realms with distinct settings
        realm1 = Mock()
        realm1.is_verify_email_enabled.return_value = False

        realm2 = Mock()
        realm2.is_verify_email_enabled.return_value = True

        realm3 = Mock()
        realm3.is_verify_email_enabled.return_value = False

        auditor._DB.get_all_realms.return_value = [realm1, realm2, realm3]
        results = list(auditor.audit())
        assert len(results) == 2  # Expect findings from realm1 and realm3, but not from realm2
