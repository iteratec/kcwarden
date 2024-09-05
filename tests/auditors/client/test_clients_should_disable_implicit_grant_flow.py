from kcwarden.auditors.client.client_should_disable_implicit_grant_flow import ClientShouldDisableImplicitGrantFlow


import pytest


from unittest.mock import Mock


class TestClientsShouldDisableImplicitGrantFlow:
    # Fixture inside the class
    @pytest.fixture
    def auditor(self, database, default_config):
        auditor_instance = ClientShouldDisableImplicitGrantFlow(database, default_config)
        auditor_instance._DB = Mock()  # Ensure that database interactions are mocked
        return auditor_instance

    @pytest.mark.parametrize(
        "is_oidc,expected",
        [
            (True, True),  # OIDC client should be considered
            (False, False),  # Non-OIDC client should not be considered
        ],
    )
    def test_consider_client_based_on_oidc_status(self, mock_client, auditor, is_oidc, expected):
        mock_client.is_oidc_client.return_value = is_oidc
        assert (
            auditor.should_consider_client(mock_client) == expected
        ), "Client consideration logic failed based on OIDC status"

    @pytest.mark.parametrize(
        "has_implicit_flow,expected",
        [
            (True, True),  # Client with implicit grant flow should be detected
            (False, False),  # Client without implicit grant flow should not be detected
        ],
    )
    def test_detect_implicit_grant_flow(self, mock_client, auditor, has_implicit_flow, expected):
        mock_client.has_implicit_flow_enabled.return_value = has_implicit_flow
        assert (
            auditor.client_uses_implicit_grant_flow(mock_client) == expected
        ), "Implicit grant flow detection logic failed"

    @pytest.mark.parametrize(
        "enable_implicit_flow,expected_count",
        [
            (True, 1),  # Client using implicit flow should result in a finding
            (False, 0),  # Client not using implicit flow should result in no findings
        ],
    )
    def test_audit_function_with_single_client(self, mock_client, auditor, enable_implicit_flow, expected_count):
        mock_client.is_oidc_client.return_value = True
        mock_client.has_implicit_flow_enabled.return_value = enable_implicit_flow
        auditor._DB.get_all_clients.return_value = [mock_client]
        results = list(auditor.audit())
        assert len(results) == expected_count, "Audit findings count mismatch for single client"

    def test_audit_function_with_multiple_clients(self, mock_client, auditor):
        mock_client.is_oidc_client.return_value = True
        mock_client.has_implicit_flow_enabled.side_effect = [True, False, True]  # Varying setups among three clients
        auditor._DB.get_all_clients.return_value = [mock_client, mock_client, mock_client]
        results = list(auditor.audit())
        assert len(results) == 2, "Audit did not yield correct number of findings for multiple clients"
