import pytest
from unittest.mock import Mock

from kcwarden.auditors.client.saml_client_assertion_signature import (
    SamlClientAssertionSignatureCheck,
)

class TestSamlClientAssertionSignatureCheck:
    @pytest.fixture
    def auditor(self, database, default_config):
        auditor_instance = SamlClientAssertionSignatureCheck(database, default_config)
        auditor_instance._DB = Mock()
        auditor_instance.is_not_ignored = Mock(return_value=True)
        return auditor_instance

    @pytest.mark.parametrize(
        "is_saml, expected",
        [
            (True, True),
            (False, False),
        ],
    )
    def test_should_consider_client(self, mock_client, auditor, is_saml, expected):
        mock_client.is_saml_client.return_value = is_saml
        assert auditor.should_consider_client(mock_client) == expected

    @pytest.mark.parametrize(
        "signature_active, expected_findings",
        [
            (True, 0),
            (False, 1),
        ],
    )
    def test_audit_logic(self, mock_client, auditor, signature_active, expected_findings):
        mock_client.is_saml_client.return_value = True
        mock_client.get_saml_assertion_signature.return_value = signature_active
        auditor._DB.get_all_clients.return_value = [mock_client]

        results = list(auditor.audit())
        assert len(results) == expected_findings

    def test_audit_mixed_clients(self, auditor):
        # 1. Secure SAML Client
        client_secure = Mock()
        client_secure.name = "secure-client"
        client_secure.client_id = "secure-client-id"
        client_secure.__str__ = Mock(return_value="secure-client")
        client_secure.is_saml_client.return_value = True
        client_secure.get_saml_assertion_signature.return_value = True

        # 2. Vulnerable SAML Client
        client_vuln = Mock()
        client_vuln.name = "vuln-client"
        client_vuln.client_id = "vuln-client-id"
        client_vuln.__str__ = Mock(return_value="vuln-client")
        client_vuln.is_saml_client.return_value = True
        client_vuln.get_saml_assertion_signature.return_value = False

        # 3. OIDC Client
        client_oidc = Mock()
        client_oidc.name = "oidc-client"
        client_oidc.client_id = "oidc-client-id"
        client_oidc.__str__ = Mock(return_value="oidc-client")
        client_oidc.is_saml_client.return_value = False
        client_oidc.get_saml_assertion_signature.return_value = False

        auditor._DB.get_all_clients.return_value = [client_secure, client_vuln, client_oidc]
        
        results = list(auditor.audit())
        
        assert len(results) == 1
        
        assert results[0]._offending_object.name == "vuln-client"