import pytest
from unittest.mock import Mock

from kcwarden.auditors.client.saml_client_onetimeuse_check import SamlClientOneTimeUseCheck

class TestSamlClientOneTimeUseCheck:
    @pytest.fixture
    def auditor(self, database, default_config):
        auditor_instance = SamlClientOneTimeUseCheck(database, default_config)
        auditor_instance._DB = Mock()
        # Mocking is_not_ignored so we only test the protocol logic in should_consider_client
        auditor_instance.is_not_ignored = Mock(return_value=True)
        return auditor_instance

    @pytest.mark.parametrize(
        "protocol, expected",
        [
            ("saml", True),            # SAML protocol - should consider
            ("openid-connect", False), # OIDC - should not consider
            ("docker-v2", False),      # Other protocols - should not consider
            (None, False),             # No protocol - should not consider
        ],
    )
    def test_should_consider_client(self, mock_client, auditor, protocol, expected):
        mock_client.get_protocol.return_value = protocol
        assert auditor.should_consider_client(mock_client) == expected

    @pytest.mark.parametrize(
        "attributes, expected_vulnerability",
        [
            # Case 1: Attribute is explicitly set to 'true' -> Not Vulnerable
            ({"saml.onetimeuse.condition": "true"}, False),
            
            # Case 2: Attribute is explicitly set to 'false' -> Vulnerable
            ({"saml.onetimeuse.condition": "false"}, True),
            
            # Case 3: Attribute is missing (default behavior) -> Vulnerable
            ({}, True),
            
            # Case 4: Attribute is set to garbage value -> Vulnerable
            ({"saml.onetimeuse.condition": "garbage"}, True),
        ],
    )
    def test_is_vulnerable(self, mock_client, auditor, attributes, expected_vulnerability):
        mock_client.get_attributes.return_value = attributes
        # is_vulnerable is a static method, so we can call it on the class or instance
        assert auditor.is_vulnerable(mock_client) == expected_vulnerability

    def test_audit_function_no_findings_secure_client(self, mock_client, auditor):
        # Setup: SAML client, OneTimeUse enabled (true)
        mock_client.get_protocol.return_value = "saml"
        mock_client.get_attributes.return_value = {"saml.onetimeuse.condition": "true"}
        
        auditor._DB.get_all_clients.return_value = [mock_client]

        results = list(auditor.audit())
        assert len(results) == 0

    def test_audit_function_with_findings_vulnerable_client(self, mock_client, auditor):
        # Setup: SAML client, OneTimeUse disabled (false)
        mock_client.get_protocol.return_value = "saml"
        mock_client.get_attributes.return_value = {"saml.onetimeuse.condition": "false"}
        
        auditor._DB.get_all_clients.return_value = [mock_client]

        results = list(auditor.audit())
        
        # We expect exactly 1 finding.
        # Note: We removed the check for .client attribute as it does not exist on Result objects.
        assert len(results) == 1

    def test_audit_function_ignores_non_saml_clients(self, mock_client, auditor):
        # Setup: OIDC client (even if it somehow had the missing attribute, it should be ignored)
        mock_client.get_protocol.return_value = "openid-connect"
        mock_client.get_attributes.return_value = {} 
        
        auditor._DB.get_all_clients.return_value = [mock_client]

        results = list(auditor.audit())
        assert len(results) == 0

    def test_audit_function_multiple_clients_mixed(self, auditor):
        # Client 1: SAML, Secure
        client_secure = Mock()
        client_secure.get_protocol.return_value = "saml"
        client_secure.get_attributes.return_value = {"saml.onetimeuse.condition": "true"}

        # Client 2: SAML, Vulnerable (Explicit false)
        client_vuln_1 = Mock()
        client_vuln_1.get_protocol.return_value = "saml"
        client_vuln_1.get_attributes.return_value = {"saml.onetimeuse.condition": "false"}

        # Client 3: SAML, Vulnerable (Missing attribute)
        client_vuln_2 = Mock()
        client_vuln_2.get_protocol.return_value = "saml"
        client_vuln_2.get_attributes.return_value = {}

        # Client 4: OIDC (Ignored)
        client_oidc = Mock()
        client_oidc.get_protocol.return_value = "openid-connect"
        client_oidc.get_attributes.return_value = {}

        auditor._DB.get_all_clients.return_value = [
            client_secure, 
            client_vuln_1, 
            client_vuln_2, 
            client_oidc
        ]

        results = list(auditor.audit())
        
        # Should find client_vuln_1 and client_vuln_2
        assert len(results) == 2