import pytest
from unittest.mock import Mock

from kcwarden.auditors.client.client_session_idle_timeout_not_set_while_sso_session_idle_timeout_too_long import (
    ClientSessionIdleTimeoutNotSetWhileSsoSessionIdleTimeoutTooLong,
)


def make_realm(sso_idle, client_idle):
    realm = Mock()
    realm.get_sso_session_idle_timeout.return_value = sso_idle
    realm.get_client_session_idle_timeout.return_value = client_idle
    return realm


class TestClientSessionIdleTimeoutNotSetWhileSsoSessionIdleTimeoutTooLong:
    @pytest.fixture
    def auditor(self, database, default_config):
        auditor_instance = ClientSessionIdleTimeoutNotSetWhileSsoSessionIdleTimeoutTooLong(database, default_config)
        auditor_instance._DB = Mock()
        return auditor_instance

    def test_should_consider_only_oidc_clients(self, auditor, mock_client):
        mock_client.is_oidc_client.return_value = True
        assert auditor.should_consider_client(mock_client) is True

        mock_client.is_oidc_client.return_value = False
        assert auditor.should_consider_client(mock_client) is False

    @pytest.mark.parametrize(
        "sso_idle, realm_client_idle, client_override, expected_finding",
        [
            # SSO not exceeding limit, no override — no finding
            (3600, 0, 0, False),
            (1800, 0, 0, False),
            # SSO not exceeding limit, override set but shorter — no finding
            (1800, 0, 900, False),
            # SSO not exceeding limit, override >= SSO — finding (general rule, threshold-independent)
            (1800, 0, 1800, True),  # override equals SSO below threshold — finding
            (1800, 0, 3600, True),  # override exceeds SSO below threshold — finding
            # SSO exceeds limit, realm client idle set — no finding (realm already limits it)
            (7200, 1800, 0, False),
            # SSO exceeds limit, realm client idle not set, client override shorter — no finding
            (7200, 0, 1800, False),
            # SSO exceeds limit, realm client idle not set, client override >= SSO — finding
            (7200, 0, 7200, True),
            (7200, 0, 9000, True),
            # SSO exceeds limit, neither realm nor client override set — finding
            (3601, 0, 0, True),
            (7200, 0, 0, True),
        ],
    )
    def test_audit_parametrized(
        self, auditor, mock_client, sso_idle, realm_client_idle, client_override, expected_finding
    ):
        mock_client.get_realm.return_value = make_realm(sso_idle, realm_client_idle)
        mock_client.get_client_session_idle_timeout_override.return_value = client_override
        auditor._DB.get_all_clients.return_value = [mock_client]

        results = list(auditor.audit())
        assert (len(results) == 1) == expected_finding

    def test_finding_contains_additional_details(self, auditor, mock_client):
        mock_client.get_realm.return_value = make_realm(7200, 0)
        mock_client.get_client_session_idle_timeout_override.return_value = 0
        auditor._DB.get_all_clients.return_value = [mock_client]

        results = list(auditor.audit())
        assert len(results) == 1
        details = results[0].additional_details
        assert details["realm_sso_session_idle_timeout"] == 7200
        assert details["realm_client_session_idle_timeout"] == 0
        assert details["client_session_idle_timeout_override"] == 0

    def test_non_oidc_client_ignored(self, auditor, mock_client):
        mock_client.is_oidc_client.return_value = False
        mock_client.get_realm.return_value = make_realm(7200, 0)
        mock_client.get_client_session_idle_timeout_override.return_value = 0
        auditor._DB.get_all_clients.return_value = [mock_client]

        results = list(auditor.audit())
        assert len(results) == 0
