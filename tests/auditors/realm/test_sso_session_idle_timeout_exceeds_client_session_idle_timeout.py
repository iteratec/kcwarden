import pytest

from kcwarden.auditors.realm.sso_session_idle_timeout_exceeds_client_session_idle_timeout import (
    SsoSessionIdleTimeoutExceedsClientSessionIdleTimeout,
)
from kcwarden.custom_types.result import Severity


class TestSsoSessionIdleTimeoutExceedsClientSessionIdleTimeout:
    @pytest.fixture
    def auditor(self, mock_database, default_config):
        return SsoSessionIdleTimeoutExceedsClientSessionIdleTimeout(mock_database, default_config)

    @pytest.mark.parametrize(
        "sso_idle, client_idle, expected_finding",
        [
            # SSO not exceeding limit, client not set — no finding
            (3600, 0, False),
            (1800, 0, False),
            # SSO not exceeding limit, client shorter — no finding
            (1800, 900, False),
            # SSO not exceeding limit, client >= SSO — finding (general rule, threshold-independent)
            (1800, 1800, True),  # client equals SSO below threshold — finding
            (1800, 3600, True),  # client exceeds SSO below threshold — finding
            # SSO exceeds limit, client not set — finding
            (3601, 0, True),
            (7200, 0, True),
            # SSO exceeds limit, client set but shorter — no finding
            (7200, 1800, False),
            (3601, 3600, False),  # client one second shorter than SSO — no finding
            # SSO exceeds limit, client set but equal or longer — finding
            (7200, 7200, True),  # client equals SSO — finding
            (7200, 9000, True),  # client exceeds SSO — finding
        ],
    )
    def test_audit_parametrized(self, auditor, mock_realm, sso_idle, client_idle, expected_finding):
        mock_realm.get_sso_session_idle_timeout.return_value = sso_idle
        mock_realm.get_client_session_idle_timeout.return_value = client_idle
        auditor._DB.get_all_realms.return_value = [mock_realm]

        results = list(auditor.audit())
        assert (len(results) == 1) == expected_finding

    @pytest.mark.parametrize(
        "sso_idle, expected_severity",
        [
            (3601, Severity.Medium),  # just above base threshold
            (28799, Severity.Medium),  # one second below high threshold
            (28800, Severity.High),  # at high threshold
            (86399, Severity.High),  # one second below critical threshold
            (86400, Severity.Critical),  # at critical threshold
            (172800, Severity.Critical),  # 48h — critical
        ],
    )
    def test_severity_scales_with_sso_idle_timeout(self, auditor, mock_realm, sso_idle, expected_severity):
        mock_realm.get_sso_session_idle_timeout.return_value = sso_idle
        mock_realm.get_client_session_idle_timeout.return_value = 0
        auditor._DB.get_all_realms.return_value = [mock_realm]

        results = list(auditor.audit())
        assert len(results) == 1
        assert results[0].severity == expected_severity

    def test_finding_contains_additional_details(self, auditor, mock_realm):
        mock_realm.get_sso_session_idle_timeout.return_value = 7200
        mock_realm.get_client_session_idle_timeout.return_value = 0
        auditor._DB.get_all_realms.return_value = [mock_realm]

        results = list(auditor.audit())
        assert len(results) == 1
        details = results[0].additional_details
        assert details["sso_session_idle_timeout"] == 7200
        assert details["client_session_idle_timeout"] == 0
