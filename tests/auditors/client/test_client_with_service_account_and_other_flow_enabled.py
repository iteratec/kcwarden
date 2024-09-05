import pytest
from unittest.mock import Mock

from kcwarden.auditors.client.client_with_service_account_and_other_flow_enabled import (
    ClientWithServiceAccountAndOtherFlowEnabled,
)


class TestClientWithServiceAccountAndOtherFlowEnabled:
    @pytest.fixture
    def auditor(self, database, default_config):
        auditor_instance = ClientWithServiceAccountAndOtherFlowEnabled(database, default_config)
        auditor_instance._DB = Mock()
        return auditor_instance

    @pytest.mark.parametrize(
        "is_oidc,is_public,service_account,expected",
        [
            (True, False, True, True),  # OIDC, confidential, service account
            (True, True, True, False),  # OIDC, public, service account
            (False, False, True, False),  # Not OIDC, confidential, service account
            (True, False, False, False),  # OIDC, confidential, no service account
        ],
    )
    def test_should_consider_client(self, mock_client, auditor, is_oidc, is_public, service_account, expected):
        mock_client.is_oidc_client.return_value = is_oidc
        mock_client.is_public.return_value = is_public
        mock_client.has_service_account_enabled.return_value = service_account
        assert auditor.should_consider_client(mock_client) == expected

    @pytest.mark.parametrize(
        "flows_enabled, expected",
        [
            ({"direct": True, "implicit": True, "standard": True, "device": False}, True),
            ({"direct": False, "implicit": False, "standard": False, "device": False}, False),
            ({"direct": True, "implicit": False, "standard": False, "device": False}, True),
            ({"direct": False, "implicit": True, "standard": False, "device": False}, True),
            ({"direct": True, "implicit": True, "standard": True, "device": True}, True),
            ({"direct": False, "implicit": False, "standard": False, "device": True}, True),
            ({"direct": True, "implicit": False, "standard": False, "device": True}, True),
            ({"direct": False, "implicit": True, "standard": False, "device": True}, True),
        ],
    )
    def test_client_has_non_service_account_flow_enabled(self, mock_client, auditor, flows_enabled, expected):
        mock_client.has_direct_access_grants_enabled.return_value = flows_enabled["direct"]
        mock_client.has_implicit_flow_enabled.return_value = flows_enabled["implicit"]
        mock_client.has_standard_flow_enabled.return_value = flows_enabled["standard"]
        mock_client.has_device_authorization_grant_flow_enabled.return_value = flows_enabled["device"]
        mock_client.allows_user_authentication.return_value = (
            flows_enabled["device"] or flows_enabled["direct"] or flows_enabled["standard"] or flows_enabled["implicit"]
        )
        assert auditor.client_has_non_service_account_flow_enabled(mock_client) == expected

    def test_audit_function_no_findings(self, mock_client, auditor):
        mock_client.is_oidc_client.return_value = True
        mock_client.is_public.return_value = False
        mock_client.has_service_account_enabled.return_value = True
        mock_client.has_direct_access_grants_enabled.return_value = False
        mock_client.has_implicit_flow_enabled.return_value = False
        mock_client.has_standard_flow_enabled.return_value = False
        mock_client.has_device_authorization_grant_flow_enabled.return_value = False
        mock_client.allows_user_authentication.return_value = False
        auditor._DB.get_all_clients.return_value = [mock_client]
        results = list(auditor.audit())
        assert len(results) == 0

    def test_audit_function_with_findings(self, mock_client, auditor):
        mock_client.is_oidc_client.return_value = True
        mock_client.is_public.return_value = False
        mock_client.has_service_account_enabled.return_value = True
        mock_client.has_direct_access_grants_enabled.return_value = True
        mock_client.has_implicit_flow_enabled.return_value = True
        mock_client.has_standard_flow_enabled.return_value = True
        mock_client.has_device_authorization_grant_flow_enabled.return_value = True
        auditor._DB.get_all_clients.return_value = [mock_client]
        results = list(auditor.audit())
        assert len(results) == 1
        finding = results[0]
        assert finding.to_dict()["additional_details"]["service_account_enabled"] is True
        assert finding.to_dict()["additional_details"]["standard_flow_enabled"] is True

    def test_audit_function_multiple_clients(self, auditor):
        # Create separate mock clients with distinct settings
        client1 = Mock()
        client1.is_oidc_client.return_value = True
        client1.is_public.return_value = False
        client1.has_service_account_enabled.return_value = True
        client1.has_direct_access_grants_enabled.return_value = True
        client1.has_implicit_flow_enabled.return_value = True
        client1.has_device_authorization_grant_flow_enabled.return_value = True
        client1.has_standard_flow_enabled.return_value = True
        client1.allows_user_authentication.return_value = True

        client2 = Mock()
        client2.is_oidc_client.return_value = True
        client2.is_public.return_value = False
        client2.has_service_account_enabled.return_value = True
        client2.has_direct_access_grants_enabled.return_value = False
        client2.has_implicit_flow_enabled.return_value = False
        client2.has_device_authorization_grant_flow_enabled.return_value = False
        client2.has_standard_flow_enabled.return_value = False
        client1.allows_user_authentication.return_value = False

        client3 = Mock()
        client3.is_oidc_client.return_value = True
        client3.is_public.return_value = False
        client3.has_service_account_enabled.return_value = True
        client3.has_direct_access_grants_enabled.return_value = True
        client3.has_implicit_flow_enabled.return_value = False
        client3.has_standard_flow_enabled.return_value = True
        client3.has_device_authorization_grant_flow_enabled.return_value = False
        client3.allows_user_authentication.return_value = True

        auditor._DB.get_all_clients.return_value = [client1, client2, client3]
        results = list(auditor.audit())
        assert len(results) == 2  # Expect findings from client1 and client3
