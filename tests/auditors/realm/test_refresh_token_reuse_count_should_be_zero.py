import pytest
from unittest.mock import Mock

from kcwarden.auditors.realm.refresh_token_reuse_count_should_be_zero import RefreshTokenReuseCountShouldBeZero


class TestRefreshTokenReuseCountShouldBeZero:
    @pytest.fixture
    def auditor(self, database, default_config):
        auditor_instance = RefreshTokenReuseCountShouldBeZero(database, default_config)
        auditor_instance._DB = Mock()
        return auditor_instance

    def test_should_consider_realm(self, mock_realm, auditor):
        assert auditor.should_consider_realm(mock_realm) is True  # Always consider unless specifically ignored

    @pytest.mark.parametrize(
        "revocation_enabled, max_reuse_count, expected",
        [
            (True, 1, True),  # Revocation enabled, but reuse allowed
            (True, 0, False),  # Revocation enabled, no reuse allowed
            (False, 1, False),  # Revocation not enabled, reuse irrelevant
        ],
    )
    def test_realm_has_refresh_token_reuse_enabled(
        self, mock_realm, auditor, revocation_enabled, max_reuse_count, expected
    ):
        mock_realm.has_refresh_token_revocation_enabled.return_value = revocation_enabled
        mock_realm.get_refresh_token_maximum_reuse_count.return_value = max_reuse_count
        assert auditor.realm_has_refresh_token_reuse_enabled(mock_realm) == expected

    def test_audit_function_no_findings(self, auditor, mock_realm):
        # Setup realm with correct refresh token settings
        mock_realm.has_refresh_token_revocation_enabled.return_value = True
        mock_realm.get_refresh_token_maximum_reuse_count.return_value = 0
        auditor._DB.get_all_realms.return_value = [mock_realm]

        results = list(auditor.audit())
        assert len(results) == 0

    def test_audit_function_with_findings(self, auditor, mock_realm):
        # Setup realm with incorrect refresh token settings
        mock_realm.has_refresh_token_revocation_enabled.return_value = True
        mock_realm.get_refresh_token_maximum_reuse_count.return_value = 1
        auditor._DB.get_all_realms.return_value = [mock_realm]

        results = list(auditor.audit())
        assert len(results) == 1

    def test_audit_function_multiple_realms(self, auditor):
        # Create separate mock realms with distinct settings
        realm1 = Mock()
        realm1.has_refresh_token_revocation_enabled.return_value = True
        realm1.get_refresh_token_maximum_reuse_count.return_value = 1

        realm2 = Mock()
        realm2.has_refresh_token_revocation_enabled.return_value = True
        realm2.get_refresh_token_maximum_reuse_count.return_value = 0

        realm3 = Mock()
        realm3.has_refresh_token_revocation_enabled.return_value = True
        realm3.get_refresh_token_maximum_reuse_count.return_value = 2

        auditor._DB.get_all_realms.return_value = [realm1, realm2, realm3]
        results = list(auditor.audit())
        assert len(results) == 2  # Expect findings from realm1 and realm3
