import pytest
from unittest.mock import Mock

from kcwarden.auditors.client.saml_client_signature import SamlClientSignatureCheck

class TestSamlClientSignatureCheck:
    @pytest.fixture
    def auditor(self, database, default_config):
        auditor_instance = SamlClientSignatureCheck(database, default_config)
        auditor_instance._DB = Mock()
        auditor_instance.is_not_ignored = Mock(return_value=True)
        return auditor_instance

    @pytest.mark.parametrize(
        "is_saml, is_ignored, expected",
        [
            (True, False, True),
            (False, False, False),
            (True, True, False),
        ],
    )
    def test_should_consider_client(self, mock_client, auditor, is_saml, is_ignored, expected):
        mock_client.is_saml_client.return_value = is_saml
        auditor.is_not_ignored.return_value = not is_ignored
        assert auditor.should_consider_client(mock_client) == expected

    def test_audit_function_secure_client(self, mock_client, auditor):
        mock_client.is_saml_client.return_value = True
        mock_client.is_saml_client_signature_required.return_value = True
        auditor._DB.get_all_clients.return_value = [mock_client]
        results = list(auditor.audit())
        assert len(results) == 0

    def test_audit_function_vulnerable_client(self, mock_client, auditor):
        mock_client.is_saml_client.return_value = True
        mock_client.is_saml_client_signature_required.return_value = False
        auditor._DB.get_all_clients.return_value = [mock_client]
        results = list(auditor.audit())
        assert len(results) == 1

    def test_audit_function_mixed_clients(self, auditor):
        client_oidc = Mock()
        client_oidc.name = "oidc-client"
        client_oidc.__str__ = Mock(return_value="oidc-client")
        client_oidc.is_saml_client.return_value = False
        client_oidc.is_saml_client_signature_required.return_value = False

        client_secure = Mock()
        client_secure.name = "secure-saml"
        client_secure.__str__ = Mock(return_value="secure-saml")
        client_secure.is_saml_client.return_value = True
        client_secure.is_saml_client_signature_required.return_value = True

        client_vuln = Mock()
        client_vuln.name = "vuln-saml"
        client_vuln.__str__ = Mock(return_value="vuln-saml")
        client_vuln.is_saml_client.return_value = True
        client_vuln.is_saml_client_signature_required.return_value = False

        auditor._DB.get_all_clients.return_value = [client_oidc, client_secure, client_vuln]
        
        results = list(auditor.audit())
        
        assert len(results) == 1
        assert results[0]._offending_object.name == "vuln-saml"