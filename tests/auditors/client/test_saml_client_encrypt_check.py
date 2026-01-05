import pytest
from unittest.mock import Mock

# Assuming the class is in a module named 'saml_client_encrypt_check' inside the package structure
# Adjust the import path below to match your actual file structure
from kcwarden.auditors.client.saml_client_encrypt_check import SamlClientEncryptCheck

class TestSamlClientEncryptCheck:
    @pytest.fixture
    def auditor(self, database, default_config):
        auditor_instance = SamlClientEncryptCheck(database, default_config)
        auditor_instance._DB = Mock()
        # Mocking is_not_ignored to return True by default so we can focus on protocol logic
        auditor_instance.is_not_ignored = Mock(return_value=True)
        return auditor_instance

    @pytest.mark.parametrize(
        "protocol, expected",
        [
            ("saml", True),           # SAML protocol - should consider
            ("openid-connect", False), # OIDC - should not consider
            ("docker-v2", False),      # Other protocols - should not consider
        ],
    )
    def test_should_consider_client(self, mock_client, auditor, protocol, expected):
        mock_client.get_protocol.return_value = protocol
        assert auditor.should_consider_client(mock_client) == expected

    @pytest.mark.parametrize(
        "attributes, expected_vulnerable",
        [
            ({"saml.encrypt": "true"}, False),   # Explicitly enabled -> Secure
            ({"saml.encrypt": "false"}, True),   # Explicitly disabled -> Vulnerable
            ({}, True),                          # Missing attribute defaults to "false" -> Vulnerable
            ({"other.attr": "value"}, True),     # Irrelevant attributes -> Vulnerable
        ],
    )
    def test_is_vulnerable(self, mock_client, auditor, attributes, expected_vulnerable):
        mock_client.get_attributes.return_value = attributes
        # Since is_vulnerable is a static method, we call it on the class or instance
        assert auditor.is_vulnerable(mock_client) == expected_vulnerable

    def test_audit_function_no_findings_secure_client(self, mock_client, auditor):
        # Setup SAML client with encryption enabled
        mock_client.get_protocol.return_value = "saml"
        mock_client.get_attributes.return_value = {"saml.encrypt": "true"}
        
        auditor._DB.get_all_clients.return_value = [mock_client]

        results = list(auditor.audit())
        assert len(results) == 0

    def test_audit_function_with_finding_insecure_client(self, mock_client, auditor):
        # Setup SAML client with encryption disabled
        mock_client.get_protocol.return_value = "saml"
        mock_client.get_attributes.return_value = {"saml.encrypt": "false"}
        
        auditor._DB.get_all_clients.return_value = [mock_client]

        results = list(auditor.audit())
        assert len(results) == 1

    def test_audit_function_with_finding_missing_attribute(self, mock_client, auditor):
        # Setup SAML client with no encryption attribute (defaults to false)
        mock_client.get_protocol.return_value = "saml"
        mock_client.get_attributes.return_value = {}
        
        auditor._DB.get_all_clients.return_value = [mock_client]

        results = list(auditor.audit())
        assert len(results) == 1

    def test_audit_function_multiple_clients_mixed(self, auditor):
        # Client 1: SAML, Secure
        client1 = Mock()
        client1.get_protocol.return_value = "saml"
        client1.get_attributes.return_value = {"saml.encrypt": "true"}

        # Client 2: SAML, Insecure (explicit)
        client2 = Mock()
        client2.get_protocol.return_value = "saml"
        client2.get_attributes.return_value = {"saml.encrypt": "false"}

        # Client 3: SAML, Insecure (implicit/missing attr)
        client3 = Mock()
        client3.get_protocol.return_value = "saml"
        client3.get_attributes.return_value = {}

        # Client 4: OIDC (Should be ignored regardless of attributes)
        client4 = Mock()
        client4.get_protocol.return_value = "openid-connect"
        client4.get_attributes.return_value = {"saml.encrypt": "false"}

        auditor._DB.get_all_clients.return_value = [client1, client2, client3, client4]
        
        results = list(auditor.audit())
        
        # We expect findings for client2 and client3 only
        assert len(results) == 2