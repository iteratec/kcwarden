import pytest
from unittest.mock import Mock

from kcwarden.auditors.client.client_with_optional_offline_access_scope import ClientWithOptionalOfflineAccessScope


class TestClientWithOptionalOfflineAccessScope:
    @pytest.fixture
    def auditor(self, database, default_config):
        auditor_instance = ClientWithOptionalOfflineAccessScope(database, default_config)
        auditor_instance._DB = Mock()
        return auditor_instance

    def test_should_consider_client(self, mock_client, auditor):
        assert auditor.should_consider_client(mock_client) is True  # Always consider unless ignored

    @pytest.mark.parametrize(
        "optional_scopes, flow_status, use_refresh_tokens, expected",
        [
            (["offline_access"], {"device": True, "direct": True, "standard": True, "implicit": False}, "true", True),
            (["offline_access"], {"device": False, "direct": True, "standard": False, "implicit": False}, "true", True),
            ([], {"device": True, "direct": True, "standard": True, "implicit": True}, "true", False),
            (
                ["offline_access"],
                {"device": False, "direct": False, "standard": False, "implicit": False},
                "true",
                False,
            ),
            (["offline_access"], {"device": True, "direct": True, "standard": True, "implicit": True}, "false", False),
        ],
    )
    def test_client_can_generate_offline_tokens(
        self, mock_client, auditor, optional_scopes, flow_status, use_refresh_tokens, expected
    ):
        mock_client.get_optional_client_scopes.return_value = optional_scopes
        mock_client.has_device_authorization_grant_flow_enabled.return_value = flow_status["device"]
        mock_client.has_direct_access_grants_enabled.return_value = flow_status["direct"]
        mock_client.has_standard_flow_enabled.return_value = flow_status["standard"]
        mock_client.has_implicit_flow_enabled.return_value = flow_status["implicit"]
        mock_client.allows_user_authentication.return_value = (
            flow_status["device"] or flow_status["direct"] or flow_status["standard"] or flow_status["implicit"]
        )
        mock_client.get_attributes.return_value = {"use.refresh.tokens": use_refresh_tokens}
        assert auditor.client_can_generate_offline_tokens(mock_client) == expected

    def test_audit_function_no_findings(self, mock_client, auditor):
        mock_client.get_optional_client_scopes.return_value = []
        mock_client.get_attributes.return_value = {"use.refresh.tokens": "false"}
        auditor._DB.get_all_clients.return_value = [mock_client]
        results = list(auditor.audit())
        assert len(results) == 0

    def test_audit_function_with_findings(self, mock_client, auditor):
        mock_client.get_optional_client_scopes.return_value = ["offline_access"]
        mock_client.has_device_authorization_grant_flow_enabled.return_value = True
        mock_client.has_direct_access_grants_enabled.return_value = True
        mock_client.has_standard_flow_enabled.return_value = True
        mock_client.has_implicit_flow_enabled.return_value = False
        mock_client.get_attributes.return_value = {"use.refresh.tokens": "true"}
        mock_client.is_public.return_value = False
        auditor._DB.get_all_clients.return_value = [mock_client]
        results = list(auditor.audit())
        assert len(results) == 1
        finding = results[0]
        assert finding.to_dict()["additional_details"]["optional_scopes"] == ["offline_access"]
        assert finding.to_dict()["additional_details"]["client_public"] == mock_client.is_public()
        assert finding.to_dict()["additional_details"]["standard_flow_enabled"] is True

    def test_audit_function_multiple_clients(self, auditor):
        # Create separate mock clients with distinct settings
        client1 = Mock()
        client1.get_optional_client_scopes.return_value = ["offline_access"]
        client1.has_device_authorization_grant_flow_enabled.return_value = True
        client1.has_direct_access_grants_enabled.return_value = True
        client1.has_standard_flow_enabled.return_value = True
        client1.has_implicit_flow_enabled.return_value = False
        client1.get_attributes.return_value = {"use.refresh.tokens": "true"}
        client1.is_public.return_value = False
        client1.is_realm_specific_client.return_value = False

        client2 = Mock()
        client2.get_optional_client_scopes.return_value = []
        client2.has_device_authorization_grant_flow_enabled.return_value = False
        client2.has_direct_access_grants_enabled.return_value = False
        client2.has_standard_flow_enabled.return_value = True
        client2.has_implicit_flow_enabled.return_value = False
        client2.get_attributes.return_value = {"use.refresh.tokens": "false"}
        client2.is_public.return_value = True
        client2.is_realm_specific_client.return_value = False

        client3 = Mock()
        client3.get_optional_client_scopes.return_value = ["offline_access"]
        client3.has_device_authorization_grant_flow_enabled.return_value = True
        client3.has_direct_access_grants_enabled.return_value = False
        client3.has_standard_flow_enabled.return_value = False
        client3.has_implicit_flow_enabled.return_value = True
        client3.get_attributes.return_value = {"use.refresh.tokens": "true"}
        client3.is_public.return_value = False
        client3.is_realm_specific_client.return_value = False

        auditor._DB.get_all_clients.return_value = [client1, client2, client3]
        results = list(auditor.audit())
        assert len(results) == 2  # Expect findings from client1 and client3
