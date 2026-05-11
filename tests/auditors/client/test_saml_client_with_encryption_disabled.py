import pytest
from unittest.mock import Mock

from kcwarden.auditors.client.saml_client_with_encryption_disabled import SamlClientWithEncryptionDisabled


class TestSamlClientWithEncryptionDisabled:
    @pytest.fixture
    def auditor(self, database, default_config):
        auditor_instance = SamlClientWithEncryptionDisabled(database, default_config)
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

    def test_audit_function_secure_client(self, mock_client, auditor):
        mock_client.is_saml_client.return_value = True
        mock_client.is_saml_encryption_enabled.return_value = True
        auditor._DB.get_all_clients.return_value = [mock_client]
        results = list(auditor.audit())
        assert len(results) == 0

    def test_audit_function_insecure_client(self, mock_client, auditor):
        mock_client.is_saml_client.return_value = True
        mock_client.is_saml_encryption_enabled.return_value = False
        auditor._DB.get_all_clients.return_value = [mock_client]
        results = list(auditor.audit())
        assert len(results) == 1

    def test_audit_mixed_clients(self, auditor, create_mock_client):
        client_secure = create_mock_client(name="secure-saml", is_saml_client=True)
        client_secure.is_saml_encryption_enabled.return_value = True

        client_vuln = create_mock_client(name="vuln-saml", is_saml_client=True)
        client_vuln.is_saml_encryption_enabled.return_value = False

        client_oidc = create_mock_client(name="oidc-client", is_saml_client=False)

        auditor._DB.get_all_clients.return_value = [client_secure, client_vuln, client_oidc]

        results = list(auditor.audit())

        assert len(results) == 1
        assert results[0]._offending_object.get_name() == "vuln-saml"
