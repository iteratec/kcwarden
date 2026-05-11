import pytest
from unittest.mock import Mock

from kcwarden.auditors.client.saml_client_with_assertion_signature_disabled import (
    SamlClientWithAssertionSignatureDisabled,
)


class TestSamlClientWithAssertionSignatureDisabled:
    @pytest.fixture
    def auditor(self, database, default_config):
        auditor_instance = SamlClientWithAssertionSignatureDisabled(database, default_config)
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

    def test_audit_mixed_clients(self, auditor, create_mock_client):
        # 1. Secure SAML Client
        client_secure = create_mock_client(name="secure-client", is_saml_client=True)
        client_secure.get_saml_assertion_signature.return_value = True

        # 2. Vulnerable SAML Client
        client_vuln = create_mock_client(name="vuln-client", is_saml_client=True)
        client_vuln.get_saml_assertion_signature.return_value = False

        # 3. OIDC Client
        client_oidc = create_mock_client(name="oidc-client", is_saml_client=False)

        auditor._DB.get_all_clients.return_value = [client_secure, client_vuln, client_oidc]

        results = list(auditor.audit())

        assert len(results) == 1

        assert results[0]._offending_object.get_name() == "vuln-client"
