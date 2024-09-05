import pytest
from unittest.mock import Mock

from kcwarden.auditors.client.client_uses_custom_redirect_uri_scheme import ClientUsesCustomRedirectUriScheme


class TestClientUsesCustomRedirectUriScheme:
    @pytest.fixture
    def auditor(self, database, default_config):
        auditor_instance = ClientUsesCustomRedirectUriScheme(database, default_config)
        auditor_instance._DB = Mock()
        return auditor_instance

    @pytest.mark.parametrize(
        "is_oidc,has_standard_flow,has_implicit_flow,expected",
        [
            (True, True, False, True),  # OIDC with standard flow
            (True, False, True, True),  # OIDC with implicit flow
            (False, True, True, False),  # Non-OIDC should be excluded
            (True, False, False, False),  # OIDC but no relevant flows
        ],
    )
    def test_should_consider_client(
        self, mock_client, auditor, is_oidc, has_standard_flow, has_implicit_flow, expected
    ):
        mock_client.is_oidc_client.return_value = is_oidc
        mock_client.has_standard_flow_enabled.return_value = has_standard_flow
        mock_client.has_implicit_flow_enabled.return_value = has_implicit_flow
        assert auditor.should_consider_client(mock_client) == expected

    @pytest.mark.parametrize(
        "redirect_uri, should_alert",
        [
            ("myapp://example.com/callback", True),  # Custom scheme
            ("https://example.com/callback", False),  # Standard HTTPS
            ("http://localhost/callback", False),  # Standard HTTP, but localhost
            ("ftp://example.com/data", True),  # FTP scheme
            ("mailto:someone@example.com", True),  # Mailto scheme
            ("/relative/path/callback", False),  # Relative path
        ],
    )
    def test_redirect_uri_uses_custom_protocol(self, auditor, redirect_uri, should_alert):
        assert auditor.redirect_uri_uses_custom_protocol(redirect_uri) == should_alert

    def test_audit_function_no_findings(self, mock_client, auditor):
        mock_client.is_default_keycloak_client.return_value = False
        mock_client.get_resolved_redirect_uris.return_value = [
            "https://example.com/callback",
            "http://localhost/callback",
        ]
        auditor._DB.get_all_clients.return_value = [mock_client]
        results = list(auditor.audit())
        assert len(results) == 0

    def test_audit_function_with_findings(self, mock_client, auditor):
        mock_client.is_default_keycloak_client.return_value = False
        mock_client.get_resolved_redirect_uris.return_value = ["myapp://example.com/callback"]
        auditor._DB.get_all_clients.return_value = [mock_client]
        results = list(auditor.audit())
        assert len(results) == 1
        finding = results[0]
        assert (
            "redirect_uri" in finding.to_dict()["additional_details"]
            and finding.to_dict()["additional_details"]["redirect_uri"] == "myapp://example.com/callback"
        )

    def test_audit_function_multiple_clients(self, mock_client, auditor):
        mock_client.is_default_keycloak_client.return_value = False
        mock_client.get_resolved_redirect_uris.side_effect = [
            ["https://secure.com/path"],
            ["myapp://example.com/callback", "https://example.com/secure"],
        ]
        auditor._DB.get_all_clients.return_value = [mock_client, mock_client]
        results = list(auditor.audit())
        assert len(results) == 1  # Expect one finding from one client
