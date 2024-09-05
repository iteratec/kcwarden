from kcwarden.auditors.client.confidential_client_should_enforce_pkce import ConfidentialClientShouldEnforcePKCE


import pytest


from unittest.mock import Mock


class TestConfidentialClientShouldEnforcePKCE:
    @pytest.fixture
    def auditor(self, database, default_config):
        auditor_instance = ConfidentialClientShouldEnforcePKCE(database, default_config)
        # Mock the database calls properly
        auditor_instance._DB = Mock()
        return auditor_instance

    @pytest.mark.parametrize(
        "is_oidc,is_public,has_flow,expected",
        [
            (True, False, True, True),  # Standard case for inclusion
            (False, False, True, False),  # Non-OIDC client should be excluded
            (True, True, True, False),  # Public client should be excluded
            (True, False, False, False),  # Client without standard flow should be excluded
        ],
    )
    def test_should_consider_client(self, confidential_client, auditor, is_oidc, is_public, has_flow, expected):
        confidential_client.is_oidc_client.return_value = is_oidc
        confidential_client.is_public.return_value = is_public
        confidential_client.has_standard_flow_enabled.return_value = has_flow
        assert auditor.should_consider_client(confidential_client) == expected

    @pytest.mark.parametrize(
        "pkce_method,should_detect",
        [
            ("S256", False),  # PKCE enforced correctly
            (None, True),  # PKCE not enforced
            ("plain", True),  # Incorrect PKCE method enforced
        ],
    )
    def test_client_does_not_enforce_pkce(self, confidential_client, auditor, pkce_method, should_detect):
        confidential_client.get_attributes.return_value = {"pkce.code.challenge.method": pkce_method}
        assert auditor.client_does_not_enforce_pkce(confidential_client) == should_detect

    def test_audit_function_no_findings(self, confidential_client, auditor):
        confidential_client.get_attributes.return_value = {"pkce.code.challenge.method": "S256"}
        auditor._DB.get_all_clients.return_value = [confidential_client]
        results = list(auditor.audit())
        assert len(results) == 0

    def test_audit_function_with_findings(self, confidential_client, auditor):
        confidential_client.get_attributes.return_value = {}
        auditor._DB.get_all_clients.return_value = [confidential_client]
        results = list(auditor.audit())
        assert len(results) == 1
        confidential_client.get_attributes.assert_called_with()

    def test_audit_function_multiple_clients(self, confidential_client, auditor):
        # Setting up different PKCE configurations
        confidential_client.get_attributes.side_effect = [
            {"pkce.code.challenge.method": "S256"},
            {},
            {"pkce.code.challenge.method": "None"},
        ]
        auditor._DB.get_all_clients.return_value = [confidential_client, confidential_client, confidential_client]
        results = list(auditor.audit())
        assert len(results) == 2  # Expect findings from two clients
