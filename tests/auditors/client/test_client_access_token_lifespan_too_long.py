import pytest
from unittest.mock import Mock

from kcwarden.auditors.client.client_access_token_lifespan_too_long import ClientAccessTokenLifespanTooLong


class TestClientAccessTokenLifespanTooLong:
    @pytest.fixture
    def auditor(self, database, default_config):
        auditor_instance = ClientAccessTokenLifespanTooLong(database, default_config)
        auditor_instance._DB = Mock()
        return auditor_instance

    @pytest.mark.parametrize(
        "is_oidc, expected",
        [
            (True, True),  # OIDC client - should consider
            (False, False),  # Not OIDC client - should not consider
        ],
    )
    def test_should_consider_client(self, mock_client, auditor, is_oidc, expected):
        mock_client.is_oidc_client.return_value = is_oidc
        assert auditor.should_consider_client(mock_client) == expected

    @pytest.mark.parametrize(
        "override_lifespan, expected",
        [
            (None, False),  # No override - should not produce a finding
            (300, False),  # 5 minutes - should not produce a finding
            (600, False),  # 10 minutes - should not produce a finding (exactly at limit)
            (601, True),  # 10 minutes + 1 second - should produce a finding
            (900, True),  # 15 minutes - should produce a finding
            (1800, True),  # 30 minutes - should produce a finding
            (3600, True),  # 60 minutes - should produce a finding
        ],
    )
    def test_client_has_access_token_lifespan_override_too_long(
        self, mock_client, auditor, override_lifespan, expected
    ):
        mock_client.get_access_token_lifespan_override.return_value = override_lifespan
        assert auditor.client_has_access_token_lifespan_override_too_long(mock_client) == expected

    def test_audit_function_no_findings_no_override(self, mock_client, auditor):
        # Setup client with no access token lifespan override
        mock_client.get_access_token_lifespan_override.return_value = None
        auditor._DB.get_all_clients.return_value = [mock_client]

        results = list(auditor.audit())
        assert len(results) == 0

    def test_audit_function_no_findings_short_override(self, mock_client, auditor):
        # Setup client with short access token lifespan override (5 minutes)
        mock_client.get_access_token_lifespan_override.return_value = 300
        mock_realm = Mock()
        mock_realm.get_access_token_lifespan.return_value = 600
        mock_client.get_realm.return_value = mock_realm
        auditor._DB.get_all_clients.return_value = [mock_client]

        results = list(auditor.audit())
        assert len(results) == 0

    def test_audit_function_no_findings_exact_limit(self, mock_client, auditor):
        # Setup client with access token lifespan override of exactly 10 minutes (600 seconds)
        mock_client.get_access_token_lifespan_override.return_value = 600
        mock_realm = Mock()
        mock_realm.get_access_token_lifespan.return_value = 300
        mock_client.get_realm.return_value = mock_realm
        auditor._DB.get_all_clients.return_value = [mock_client]

        results = list(auditor.audit())
        assert len(results) == 0

    def test_audit_function_with_findings_long_override(self, mock_client, auditor):
        # Setup client with long access token lifespan override (15 minutes)
        mock_client.get_access_token_lifespan_override.return_value = 900
        mock_realm = Mock()
        mock_realm.get_access_token_lifespan.return_value = 300
        mock_client.get_realm.return_value = mock_realm
        auditor._DB.get_all_clients.return_value = [mock_client]

        results = list(auditor.audit())
        assert len(results) == 1

        # Verify the finding contains expected additional details
        finding = results[0]
        assert finding.additional_details["client_access_token_lifespan"] == 900
        assert finding.additional_details["realm_access_token_lifespan"] == 300

    def test_audit_function_multiple_clients_mixed_overrides(self, auditor):
        # Create separate mock clients with distinct token lifespan overrides
        mock_realm = Mock()
        mock_realm.get_access_token_lifespan.return_value = 300

        client1 = Mock()
        client1.get_access_token_lifespan_override.return_value = None  # No override - OK
        client1.get_realm.return_value = mock_realm
        client1.is_oidc_client.return_value = True

        client2 = Mock()
        client2.get_access_token_lifespan_override.return_value = 300  # 5 minutes - OK
        client2.get_realm.return_value = mock_realm
        client2.is_oidc_client.return_value = True

        client3 = Mock()
        client3.get_access_token_lifespan_override.return_value = 1800  # 30 minutes - Too long
        client3.get_realm.return_value = mock_realm
        client3.is_oidc_client.return_value = True

        client4 = Mock()
        client4.get_access_token_lifespan_override.return_value = 900  # 15 minutes - Too long
        client4.get_realm.return_value = mock_realm
        client4.is_oidc_client.return_value = True

        # client5 is not an OIDC client - should be ignored
        client5 = Mock()
        client5.get_access_token_lifespan_override.return_value = 1800  # 30 minutes but ignored
        client5.get_realm.return_value = mock_realm
        client5.is_oidc_client.return_value = False

        auditor._DB.get_all_clients.return_value = [client1, client2, client3, client4, client5]
        results = list(auditor.audit())
        assert len(results) == 2  # Expect findings from client3 and client4 only

    def test_audit_function_edge_case_zero_override(self, mock_client, auditor):
        # Edge case: client with 0 second override that means unlimited
        mock_client.get_access_token_lifespan_override.return_value = 0
        mock_realm = Mock()
        mock_realm.get_access_token_lifespan.return_value = 300
        mock_client.get_realm.return_value = mock_realm
        auditor._DB.get_all_clients.return_value = [mock_client]

        results = list(auditor.audit())
        assert len(results) == 1

    def test_audit_function_edge_case_very_long_override(self, mock_client, auditor):
        # Edge case: client with very long override (24 hours)
        mock_client.get_access_token_lifespan_override.return_value = 86400  # 24 hours
        mock_realm = Mock()
        mock_realm.get_access_token_lifespan.return_value = 300
        mock_client.get_realm.return_value = mock_realm
        auditor._DB.get_all_clients.return_value = [mock_client]

        results = list(auditor.audit())
        assert len(results) == 1

        finding = results[0]
        assert finding.additional_details["client_access_token_lifespan"] == 86400
