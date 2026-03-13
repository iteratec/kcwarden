from unittest.mock import Mock

import pytest

from kcwarden.auditors.realm.offline_session_max_lifespan_disabled import OfflineSessionMaxLifespanDisabled


class TestOfflineSessionMaxLifespanDisabled:
    @pytest.fixture
    def auditor(self, mock_database, default_config):
        return OfflineSessionMaxLifespanDisabled(mock_database, default_config)

    def test_should_consider_realm(self, mock_realm, auditor):
        assert auditor.should_consider_realm(mock_realm) is True

    @pytest.mark.parametrize(
        "is_enabled, expected",
        [
            (True, False),  # Max lifespan enabled - no finding
            (False, True),  # Max lifespan disabled - finding
        ],
    )
    def test_realm_has_offline_session_max_lifespan_disabled(self, mock_realm, auditor, is_enabled, expected):
        mock_realm.is_offline_session_max_lifespan_enabled.return_value = is_enabled
        assert auditor.realm_has_offline_session_max_lifespan_disabled(mock_realm) == expected

    def test_audit_function_no_findings(self, auditor, mock_realm):
        mock_realm.is_offline_session_max_lifespan_enabled.return_value = True
        auditor._DB.get_all_realms.return_value = [mock_realm]

        results = list(auditor.audit())
        assert len(results) == 0

    def test_audit_function_with_findings(self, auditor, mock_realm):
        mock_realm.is_offline_session_max_lifespan_enabled.return_value = False
        auditor._DB.get_all_realms.return_value = [mock_realm]

        results = list(auditor.audit())
        assert len(results) == 1

    def test_audit_function_multiple_realms(self, auditor):
        realm1 = Mock()
        realm1.is_offline_session_max_lifespan_enabled.return_value = False

        realm2 = Mock()
        realm2.is_offline_session_max_lifespan_enabled.return_value = True

        realm3 = Mock()
        realm3.is_offline_session_max_lifespan_enabled.return_value = False

        auditor._DB.get_all_realms.return_value = [realm1, realm2, realm3]
        results = list(auditor.audit())
        assert len(results) == 2
