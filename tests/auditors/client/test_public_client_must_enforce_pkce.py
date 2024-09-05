from kcwarden.auditors.client.public_clients_must_enforce_pkce import PublicClientsMustEnforcePKCE


import pytest


from unittest.mock import Mock


class TestPublicClientMustEnforcePKCE:
    @pytest.fixture
    def auditor(self, database, default_config):
        auditor_instance = PublicClientsMustEnforcePKCE(database, default_config)
        # Mock the database calls properly
        auditor_instance._DB = Mock()
        return auditor_instance

    @pytest.mark.parametrize(
        "is_oidc,is_public,has_flow,expected",
        [
            (True, True, True, True),  # Standard case for inclusion
            (False, True, True, False),  # Non-OIDC client should be excluded
            (True, False, True, False),  # Confidential client should be excluded
            (True, True, False, False),  # Client without standard flow should be excluded
        ],
    )
    def test_should_consider_client(self, mock_client, auditor, is_oidc, is_public, has_flow, expected):
        mock_client.is_oidc_client.return_value = is_oidc
        mock_client.is_public.return_value = is_public
        mock_client.has_standard_flow_enabled.return_value = has_flow
        assert auditor.should_consider_client(mock_client) == expected

    @pytest.mark.parametrize(
        "pkce_method,should_detect",
        [
            ("S256", False),  # PKCE enforced correctly
            (None, True),  # PKCE not enforced
            ("plain", True),  # Incorrect PKCE method enforced
        ],
    )
    def test_client_does_not_enforce_pkce(self, public_client, auditor, pkce_method, should_detect):
        public_client.get_attributes.return_value = {"pkce.code.challenge.method": pkce_method}
        assert auditor.client_does_not_enforce_pkce(public_client) == should_detect

    def test_audit_function_no_findings(self, public_client, auditor):
        public_client.get_attributes.return_value = {"pkce.code.challenge.method": "S256"}
        auditor._DB.get_all_clients.return_value = [public_client]
        results = list(auditor.audit())
        assert len(results) == 0

    def test_audit_function_with_findings(self, public_client, auditor):
        public_client.get_attributes.return_value = {}
        auditor._DB.get_all_clients.return_value = [public_client]
        results = list(auditor.audit())
        assert len(results) == 1
        public_client.get_attributes.assert_called_with()

    def test_audit_function_multiple_clients(self, public_client, auditor):
        # Setting up different PKCE configurations
        public_client.get_attributes.side_effect = [
            {"pkce.code.challenge.method": "S256"},
            {},
            {"pkce.code.challenge.method": "None"},
        ]
        auditor._DB.get_all_clients.return_value = [public_client, public_client, public_client]
        results = list(auditor.audit())
        assert len(results) == 2  # Expect findings from two clients
