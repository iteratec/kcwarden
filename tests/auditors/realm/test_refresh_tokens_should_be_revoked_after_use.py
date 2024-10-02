from unittest.mock import Mock

import pytest

from kcwarden.auditors.realm.refresh_tokens_should_be_revoked_after_use import RefreshTokensShouldBeRevokedAfterUse


class TestRefreshTokensShouldBeRevokedAfterUse:
    @pytest.fixture
    def auditor(self, mock_database, default_config):
        return RefreshTokensShouldBeRevokedAfterUse(mock_database, default_config)

    def test_should_consider_realm(self, mock_realm, auditor):
        assert auditor.should_consider_realm(mock_realm) is True  # Always consider unless specifically ignored

    @pytest.mark.parametrize(
        "revocation_enabled, expected",
        [
            (True, False),  # Revocation enabled, should not produce a finding
            (False, True),  # Revocation disabled, should produce a finding
        ],
    )
    def test_realm_has_refresh_token_revocation_disabled(self, mock_realm, auditor, revocation_enabled, expected):
        mock_realm.has_refresh_token_revocation_enabled.return_value = revocation_enabled
        assert auditor.realm_has_refresh_token_revocation_disabled(mock_realm) == expected

    def test_audit_function_no_findings(self, auditor, mock_realm):
        # Setup realm with refresh token revocation enabled
        mock_realm.has_refresh_token_revocation_enabled.return_value = True
        auditor._DB.get_all_realms.return_value = [mock_realm]

        results = list(auditor.audit())
        assert len(results) == 0

    def test_audit_function_with_findings(self, auditor, mock_realm):
        # Setup realm with refresh token revocation disabled
        mock_realm.has_refresh_token_revocation_enabled.return_value = False
        auditor._DB.get_all_realms.return_value = [mock_realm]

        results = list(auditor.audit())
        assert len(results) == 1

    def test_audit_function_multiple_realms(self, auditor):
        # Create separate mock realms with distinct settings
        realm1 = Mock()
        realm1.has_refresh_token_revocation_enabled.return_value = False

        realm2 = Mock()
        realm2.has_refresh_token_revocation_enabled.return_value = True

        realm3 = Mock()
        realm3.has_refresh_token_revocation_enabled.return_value = False

        auditor._DB.get_all_realms.return_value = [realm1, realm2, realm3]
        results = list(auditor.audit())
        assert len(results) == 2  # Expect findings from realm1 and realm3
