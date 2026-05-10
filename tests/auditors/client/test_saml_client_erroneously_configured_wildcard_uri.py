import pytest
from unittest.mock import Mock

from kcwarden.auditors.client.saml_client_erroneously_configured_wildcard_uri import (
    SamlClientHasErroneouslyConfiguredWildcardURI,
)


class TestSamlClientHasErroneouslyConfiguredWildcardURI:
    @pytest.fixture
    def auditor(self, database, default_config):
        auditor_instance = SamlClientHasErroneouslyConfiguredWildcardURI(database, default_config)
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
        "uri, expected_finding",
        [
            # Safe URIs — wildcard in path, not domain
            ("https://example.com/*", False),
            ("https://example.com/path*", False),
            ("https://example.com", False),
            # Global wildcard — excluded (handled by a dedicated check)
            ("*", False),
            # Dangerous: wildcard at end of domain, no path
            ("https://example.com*", True),
            # Wildcard in domain with a trailing path — not last character, so Keycloak does not expand it
            ("https://example.com*/callback", False),
            # Dangerous: scheme-less URI parsed entirely as path with no slash
            ("example.com*", True),
        ],
    )
    def test_audit_logic(self, mock_client, auditor, uri, expected_finding):
        mock_client.is_saml_client.return_value = True
        mock_client.get_resolved_redirect_uris.return_value = [uri]
        auditor._DB.get_all_clients.return_value = [mock_client]

        results = list(auditor.audit())
        assert len(results) == (1 if expected_finding else 0)
        if expected_finding:
            assert results[0].additional_details["redirect_uri"] == uri

    def test_audit_mixed_clients(self, auditor, create_mock_client):
        # Safe SAML client — wildcard only in path
        client_safe = create_mock_client(name="safe-saml", is_saml_client=True)
        client_safe.get_resolved_redirect_uris.return_value = ["https://example.com/*"]

        # Vulnerable SAML client — wildcard in domain
        client_vuln = create_mock_client(name="vuln-saml", is_saml_client=True)
        client_vuln.get_resolved_redirect_uris.return_value = ["https://example.com*"]

        # OIDC client — should be ignored regardless of URI
        client_oidc = create_mock_client(name="oidc-client", is_saml_client=False)
        client_oidc.get_resolved_redirect_uris.return_value = ["https://example.com*"]

        auditor._DB.get_all_clients.return_value = [client_safe, client_vuln, client_oidc]

        results = list(auditor.audit())

        assert len(results) == 1
        assert results[0]._offending_object.get_name() == "vuln-saml"
        assert results[0].additional_details["redirect_uri"] == "https://example.com*"

    def test_audit_multiple_bad_uris(self, auditor, create_mock_client):
        client_multi = create_mock_client(name="multi-bad", is_saml_client=True)
        client_multi.get_resolved_redirect_uris.return_value = [
            "https://ok.com/*",
            "https://bad.com*",
            "https://also-bad.com*",
        ]

        auditor._DB.get_all_clients.return_value = [client_multi]

        results = list(auditor.audit())

        assert len(results) == 2
        uris = {r.additional_details["redirect_uri"] for r in results}
        assert uris == {"https://bad.com*", "https://also-bad.com*"}
