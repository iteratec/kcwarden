import pytest
from unittest.mock import Mock

from kcwarden.auditors.client.saml_client_wildcard_redirect_uris import (
    SamlClientWildcardRedirectUriCheck,
)

class TestSamlClientWildcardRedirectUriCheck:
    @pytest.fixture
    def auditor(self, database, default_config):
        auditor_instance = SamlClientWildcardRedirectUriCheck(database, default_config)
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

    @pytest.mark.parametrize(
        "uris, expected_findings",
        [
            ([], []),
            (None, []),
            (["https://valid.com"], []),
            (["https://valid.com/*"], ["https://valid.com/*"]),
            (["https://valid.com", "https://bad.com/*"], ["https://bad.com/*"]),
            (["https://valid.com/path*"], ["https://valid.com/path*"]),
            ([" * "], [" * "]),
            (["https://domain.com/*?query=1"], []),
        ],
    )
    def test_get_vulnerable_uris_logic(self, mock_client, auditor, uris, expected_findings):
        mock_client.get_resolved_redirect_uris.return_value = uris
        bad_uris = auditor.get_vulnerable_uris(mock_client)
        assert bad_uris == expected_findings

    def test_audit_function_mixed_clients(self, auditor):
        client_safe = Mock()
        client_safe.name = "safe-saml"
        client_safe.__str__ = Mock(return_value="safe-saml")
        client_safe.is_saml_client.return_value = True
        client_safe.get_resolved_redirect_uris.return_value = ["https://ok.com"]
        
        client_vuln = Mock()
        client_vuln.name = "vuln-saml"
        client_vuln.__str__ = Mock(return_value="vuln-saml")
        client_vuln.is_saml_client.return_value = True
        client_vuln.get_resolved_redirect_uris.return_value = ["https://bad.com/*"]

        client_oidc = Mock()
        client_oidc.name = "oidc-client"
        client_oidc.__str__ = Mock(return_value="oidc-client")
        client_oidc.is_saml_client.return_value = False
        client_oidc.get_resolved_redirect_uris.return_value = ["https://bad-oidc.com/*"]

        auditor._DB.get_all_clients.return_value = [client_safe, client_vuln, client_oidc]
        
        results = list(auditor.audit())
        
        assert len(results) == 1
        assert results[0]._offending_object.name == "vuln-saml"
        assert results[0].additional_details["vulnerable_uris"] == ["https://bad.com/*"]