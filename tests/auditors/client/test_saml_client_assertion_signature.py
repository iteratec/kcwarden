import pytest
from unittest.mock import Mock

# Adjust the import path to match where you saved the class
from kcwarden.auditors.client.saml_client_assertion_signature import (
    SamlClientAssertionSignatureCheck,
)


class TestSamlClientAssertionSignatureCheck:
    @pytest.fixture
    def auditor(self, database, default_config):
        auditor_instance = SamlClientAssertionSignatureCheck(database, default_config)
        auditor_instance._DB = Mock()
        # Mock is_not_ignored to ensure we are testing specific logic, 
        # though standard mock_clients usually pass the base check by default.
        auditor_instance.is_not_ignored = Mock(return_value=True)
        return auditor_instance

    @pytest.mark.parametrize(
        "protocol, expected",
        [
            ("saml", True),  # SAML client - should consider
            ("openid-connect", False),  # OIDC client - should not consider
            ("docker-v2", False),  # Other protocols - should not consider
            (None, False),  # No protocol - should not consider
        ],
    )
    def test_should_consider_client(self, mock_client, auditor, protocol, expected):
        mock_client.get_protocol.return_value = protocol
        assert auditor.should_consider_client(mock_client) == expected

    @pytest.mark.parametrize(
        "attribute_value, expected_vulnerable",
        [
            ("true", False),   # Explicitly signed -> Secure
            ("false", True),   # Explicitly not signed -> Vulnerable
            (None, True),      # Attribute missing (defaults to false) -> Vulnerable
            ("garbage", True), # Invalid value (not "true") -> Vulnerable
            ("", True),        # Empty string -> Vulnerable
        ],
    )
    def test_is_vulnerable_logic(self, mock_client, attribute_value, expected_vulnerable):
        # Setup the attributes dictionary
        attributes = {}
        if attribute_value is not None:
            attributes["saml.assertion.signature"] = attribute_value
        
        mock_client.get_attributes.return_value = attributes
        
        # is_vulnerable is a static method, can be called on class or instance
        assert SamlClientAssertionSignatureCheck.is_vulnerable(mock_client) == expected_vulnerable

    def test_audit_function_no_findings(self, mock_client, auditor):
        # Setup secure SAML client
        mock_client.get_protocol.return_value = "saml"
        mock_client.get_attributes.return_value = {"saml.assertion.signature": "true"}
        
        auditor._DB.get_all_clients.return_value = [mock_client]

        results = list(auditor.audit())
        assert len(results) == 0

    def test_audit_function_with_finding(self, mock_client, auditor):
        # Setup vulnerable SAML client (explicit false)
        mock_client.get_protocol.return_value = "saml"
        mock_client.get_attributes.return_value = {"saml.assertion.signature": "false"}
        
        auditor._DB.get_all_clients.return_value = [mock_client]

        results = list(auditor.audit())
        assert len(results) == 1

    def test_audit_function_with_finding_default_value(self, mock_client, auditor):
        # Setup vulnerable SAML client (missing attribute)
        mock_client.get_protocol.return_value = "saml"
        mock_client.get_attributes.return_value = {}
        
        auditor._DB.get_all_clients.return_value = [mock_client]

        results = list(auditor.audit())
        assert len(results) == 1

    def test_audit_function_multiple_clients_mixed(self, auditor):
        # 1. Secure SAML Client
        client_secure = Mock()
        client_secure.get_protocol.return_value = "saml"
        client_secure.get_attributes.return_value = {"saml.assertion.signature": "true"}

        # 2. Vulnerable SAML Client
        client_vuln = Mock()
        client_vuln.get_protocol.return_value = "saml"
        client_vuln.get_attributes.return_value = {"saml.assertion.signature": "false"}

        # 3. Non-SAML Client (OIDC) - Should be ignored even if attributes missing
        client_oidc = Mock()
        client_oidc.get_protocol.return_value = "openid-connect"
        client_oidc.get_attributes.return_value = {} 

        auditor._DB.get_all_clients.return_value = [client_secure, client_vuln, client_oidc]
        
        results = list(auditor.audit())
        assert len(results) == 1  # Only client_vuln should return a finding