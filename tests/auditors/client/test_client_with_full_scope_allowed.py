import pytest
from unittest.mock import Mock

from kcwarden.auditors.client.client_with_full_scope_allowed import ClientWithFullScopeAllowed


class TestClientWithFullScopeAllowed:
    @pytest.fixture
    def auditor(self, database, default_config):
        auditor_instance = ClientWithFullScopeAllowed(database, default_config)
        auditor_instance._DB = Mock()
        return auditor_instance

    @pytest.mark.parametrize(
        "allows_user_auth, expected",
        [
            (True, True),  # User auth allowed
            (False, False),  # User auth not allowed
        ],
    )
    def test_should_consider_client(self, mock_client, auditor, allows_user_auth, expected):
        mock_client.allows_user_authentication.return_value = allows_user_auth
        assert auditor.should_consider_client(mock_client) == expected

    @pytest.mark.parametrize(
        "full_scope_allowed, expected",
        [
            (True, True),  # Full scope allowed
            (False, False),  # Full scope not allowed
        ],
    )
    def test_client_has_full_scope_allowed(self, mock_client, auditor, full_scope_allowed, expected):
        mock_client.has_full_scope_allowed.return_value = full_scope_allowed
        assert auditor.client_has_full_scope_allowed(mock_client) == expected

    def test_audit_function_no_findings(self, mock_client, auditor):
        mock_client.has_full_scope_allowed.return_value = False
        mock_client.get_default_client_scopes.return_value = ["email", "profile"]
        mock_client.get_optional_client_scopes.return_value = ["address"]
        auditor._DB.get_all_clients.return_value = [mock_client]
        results = list(auditor.audit())
        assert len(results) == 0

    def test_audit_function_with_findings(self, mock_client, auditor):
        mock_client.has_full_scope_allowed.return_value = True
        mock_client.get_default_client_scopes.return_value = ["email", "profile"]
        mock_client.get_optional_client_scopes.return_value = ["address"]
        auditor._DB.get_all_clients.return_value = [mock_client]
        results = list(auditor.audit())
        assert len(results) == 1
        finding = results[0]
        assert finding.to_dict()["additional_details"]["default_scopes"] == ["email", "profile"]
        assert finding.to_dict()["additional_details"]["optional_scopes"] == ["address"]

    def test_audit_function_multiple_clients(self, auditor):
        # Create separate mock clients with distinct settings
        client1 = Mock()
        client1.has_full_scope_allowed.return_value = True
        client1.get_default_client_scopes.return_value = ["email"]
        client1.get_optional_client_scopes.return_value = ["profile"]
        client1.is_realm_specific_client.return_value = False

        client2 = Mock()
        client2.has_full_scope_allowed.return_value = False
        client2.get_default_client_scopes.return_value = ["email", "profile"]
        client2.get_optional_client_scopes.return_value = ["address"]
        client2.is_realm_specific_client.return_value = False

        client3 = Mock()
        client3.has_full_scope_allowed.return_value = True
        client3.get_default_client_scopes.return_value = ["offline_access"]
        client3.get_optional_client_scopes.return_value = []
        client3.is_realm_specific_client.return_value = False

        auditor._DB.get_all_clients.return_value = [client1, client2, client3]
        results = list(auditor.audit())
        assert len(results) == 2  # Expect findings from client1 and client3
