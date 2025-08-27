from unittest.mock import Mock

import pytest

from kcwarden.auditors.realm.access_token_lifespan_too_long import AccessTokenLifespanTooLong


class TestAccessTokenLifespanTooLong:
    @pytest.fixture
    def auditor(self, mock_database, default_config):
        return AccessTokenLifespanTooLong(mock_database, default_config)

    def test_should_consider_realm(self, mock_realm, auditor):
        assert auditor.should_consider_realm(mock_realm) is True  # Always consider unless specifically ignored

    @pytest.mark.parametrize(
        "lifespan_seconds, expected",
        [
            (300, False),  # 5 minutes - should not produce a finding
            (600, False),  # 10 minutes - should not produce a finding (exactly at limit)
            (601, True),  # 10 minutes + 1 second - should produce a finding
            (0, True),  # unlimited - should produce a finding
            (900, True),  # 15 minutes - should produce a finding
            (1800, True),  # 30 minutes - should produce a finding
            (3600, True),  # 60 minutes - should produce a finding
        ],
    )
    def test_realm_has_access_token_lifespan_too_long(self, mock_realm, auditor, lifespan_seconds, expected):
        mock_realm.get_access_token_lifespan.return_value = lifespan_seconds
        assert auditor.realm_has_access_token_lifespan_too_long(mock_realm) == expected

    def test_audit_function_no_findings_short_lifespan(self, auditor, mock_realm):
        # Setup realm with access token lifespan of 5 minutes (300 seconds)
        mock_realm.get_access_token_lifespan.return_value = 300
        auditor._DB.get_all_realms.return_value = [mock_realm]

        results = list(auditor.audit())
        assert len(results) == 0

    def test_audit_function_no_findings_exact_limit(self, auditor, mock_realm):
        # Setup realm with access token lifespan of exactly 10 minutes (600 seconds)
        mock_realm.get_access_token_lifespan.return_value = 600
        auditor._DB.get_all_realms.return_value = [mock_realm]

        results = list(auditor.audit())
        assert len(results) == 0

    def test_audit_function_with_findings_long_lifespan(self, auditor, mock_realm):
        # Setup realm with access token lifespan of 15 minutes (900 seconds)
        mock_realm.get_access_token_lifespan.return_value = 900
        auditor._DB.get_all_realms.return_value = [mock_realm]

        results = list(auditor.audit())
        assert len(results) == 1

        # Verify the finding contains expected additional details
        finding = results[0]
        assert finding.additional_details["realm_access_token_lifespan"] == 900

    def test_audit_function_multiple_realms_mixed_lifespans(self, auditor):
        # Create separate mock realms with distinct token lifespans
        realm1 = Mock()
        realm1.get_access_token_lifespan.return_value = 300  # 5 minutes - OK

        realm2 = Mock()
        realm2.get_access_token_lifespan.return_value = 600  # 10 minutes - OK (at limit)

        realm3 = Mock()
        realm3.get_access_token_lifespan.return_value = 1800  # 30 minutes - Too long

        realm4 = Mock()
        realm4.get_access_token_lifespan.return_value = 900  # 15 minutes - Too long

        auditor._DB.get_all_realms.return_value = [realm1, realm2, realm3, realm4]
        results = list(auditor.audit())
        assert len(results) == 2  # Expect findings from realm3 and realm4

    def test_audit_function_edge_case_zero_lifespan(self, auditor, mock_realm):
        # Edge case: realm with 0 second lifespan that means unlimited
        mock_realm.get_access_token_lifespan.return_value = 0
        auditor._DB.get_all_realms.return_value = [mock_realm]

        results = list(auditor.audit())
        assert len(results) == 1

    def test_audit_function_edge_case_very_long_lifespan(self, auditor, mock_realm):
        # Edge case: realm with a very long lifespan (24 hours)
        mock_realm.get_access_token_lifespan.return_value = 86400  # 24 hours
        auditor._DB.get_all_realms.return_value = [mock_realm]

        results = list(auditor.audit())
        assert len(results) == 1

        finding = results[0]
        assert finding.additional_details["realm_access_token_lifespan"] == 86400
