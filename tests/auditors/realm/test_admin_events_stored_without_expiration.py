from unittest.mock import Mock

import pytest

from kcwarden.auditors.realm.admin_events_stored_without_expiration import AdminEventsStoredWithoutExpiration


class TestAdminEventsStoredWithoutExpiration:
    @pytest.fixture
    def auditor(self, mock_database, default_config):
        return AdminEventsStoredWithoutExpiration(mock_database, default_config)

    def test_should_consider_realm(self, mock_realm, auditor):
        assert auditor.should_consider_realm(mock_realm) is True

    @pytest.mark.parametrize(
        "events_enabled, expiration, expected",
        [
            (False, 0, False),  # Admin events disabled - no finding
            (False, 3600, False),  # Admin events disabled, expiration set - no finding
            (True, 3600, False),  # Admin events enabled, expiration set - no finding
            (True, 0, True),  # Admin events enabled, no expiration - finding
        ],
    )
    def test_realm_stores_admin_events_without_expiration(
        self, mock_realm, auditor, events_enabled, expiration, expected
    ):
        mock_realm.is_admin_events_enabled.return_value = events_enabled
        mock_realm.get_admin_events_expiration.return_value = expiration
        assert auditor.realm_stores_admin_events_without_expiration(mock_realm) == expected

    def test_audit_function_no_findings(self, auditor, mock_realm):
        mock_realm.is_admin_events_enabled.return_value = True
        mock_realm.get_admin_events_expiration.return_value = 86400
        auditor._DB.get_all_realms.return_value = [mock_realm]

        results = list(auditor.audit())
        assert len(results) == 0

    def test_audit_function_with_findings(self, auditor, mock_realm):
        mock_realm.is_admin_events_enabled.return_value = True
        mock_realm.get_admin_events_expiration.return_value = 0
        auditor._DB.get_all_realms.return_value = [mock_realm]

        results = list(auditor.audit())
        assert len(results) == 1

    def test_audit_function_multiple_realms(self, auditor):
        realm1 = Mock()
        realm1.is_admin_events_enabled.return_value = True
        realm1.get_admin_events_expiration.return_value = 0

        realm2 = Mock()
        realm2.is_admin_events_enabled.return_value = True
        realm2.get_admin_events_expiration.return_value = 3600

        realm3 = Mock()
        realm3.is_admin_events_enabled.return_value = False
        realm3.get_admin_events_expiration.return_value = 0

        auditor._DB.get_all_realms.return_value = [realm1, realm2, realm3]
        results = list(auditor.audit())
        assert len(results) == 1
