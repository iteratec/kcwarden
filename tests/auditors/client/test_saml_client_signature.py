import pytest
from unittest.mock import Mock

# Adjust the import path below to match your project structure
from kcwarden.auditors.client.saml_client_signature import SamlClientSignatureCheck

class TestSamlClientSignatureCheck:
    @pytest.fixture
    def auditor(self, database, default_config):
        auditor_instance = SamlClientSignatureCheck(database, default_config)
        auditor_instance._DB = Mock()
        # Mocking the base class 'is_not_ignored' to isolate the logic specific to this auditor
        auditor_instance.is_not_ignored = Mock(return_value=True)
        return auditor_instance

    @pytest.mark.parametrize(
        "protocol, is_ignored, expected",
        [
            ("saml", False, True),   # SAML client and not ignored -> Consider
            ("oidc", False, False),  # OIDC client -> Do not consider
            ("saml", True, False),   # SAML client but ignored -> Do not consider
        ],
    )
    def test_should_consider_client(self, mock_client, auditor, protocol, is_ignored, expected):
        mock_client.get_protocol.return_value = protocol
        auditor.is_not_ignored.return_value = not is_ignored
        
        assert auditor.should_consider_client(mock_client) == expected

    @pytest.mark.parametrize(
        "attribute_value, expected_vulnerable",
        [
            ("true", False),   # Explicitly set to true -> Safe
            ("false", True),   # Explicitly set to false -> Vulnerable
            (None, True),      # Attribute missing (defaults to "false") -> Vulnerable
            ("True", True),    # Case sensitivity check (code checks != "true") -> Vulnerable
            ("1", True),       # Any value other than "true" -> Vulnerable
        ],
    )
    def test_is_vulnerable(self, mock_client, auditor, attribute_value, expected_vulnerable):
        attributes = {}
        if attribute_value is not None:
            attributes["saml.client.signature"] = attribute_value
        
        mock_client.get_attributes.return_value = attributes
        
        # Since is_vulnerable is a static method in your code, we can call it 
        # via the class or the instance. Using instance to match typical flow.
        assert auditor.is_vulnerable(mock_client) == expected_vulnerable

    def test_audit_function_no_findings(self, mock_client, auditor):
        # Setup: SAML client with signature verification enabled
        mock_client.get_protocol.return_value = "saml"
        mock_client.get_attributes.return_value = {"saml.client.signature": "true"}
        
        auditor._DB.get_all_clients.return_value = [mock_client]
        
        results = list(auditor.audit())
        assert len(results) == 0

    def test_audit_function_with_finding_explicit_false(self, mock_client, auditor):
        # Setup: SAML client with signature verification explicitly disabled
        mock_client.get_protocol.return_value = "saml"
        mock_client.get_attributes.return_value = {"saml.client.signature": "false"}
        
        auditor._DB.get_all_clients.return_value = [mock_client]
        
        results = list(auditor.audit())
        assert len(results) == 1

    def test_audit_function_with_finding_missing_attribute(self, mock_client, auditor):
        # Setup: SAML client with missing attribute (defaults to false)
        mock_client.get_protocol.return_value = "saml"
        mock_client.get_attributes.return_value = {}
        
        auditor._DB.get_all_clients.return_value = [mock_client]
        
        results = list(auditor.audit())
        assert len(results) == 1

    def test_audit_function_mixed_clients(self, auditor):
        # 1. OIDC client (Ignored by protocol)
        client1 = Mock()
        client1.get_protocol.return_value = "oidc"
        
        # 2. SAML Client (Safe)
        client2 = Mock()
        client2.get_protocol.return_value = "saml"
        client2.get_attributes.return_value = {"saml.client.signature": "true"}
        
        # 3. SAML Client (Vulnerable)
        client3 = Mock()
        client3.get_protocol.return_value = "saml"
        client3.get_attributes.return_value = {"saml.client.signature": "false"}

        auditor._DB.get_all_clients.return_value = [client1, client2, client3]
        
        results = list(auditor.audit())
        assert len(results) == 1