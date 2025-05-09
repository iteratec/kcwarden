import pytest
from unittest.mock import Mock

from kcwarden.auditors.client.client_should_not_use_wildcard_redirect_uri import ClientShouldNotUseWildcardRedirectURI


class TestClientShouldNotUseWildcardRedirectURI:
    @pytest.fixture
    def auditor(self, database, default_config):
        auditor_instance = ClientShouldNotUseWildcardRedirectURI(database, default_config)
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

    # noinspection HttpUrlsUsage
    @pytest.mark.parametrize(
        "redirect_uri, should_alert",
        [
            ("https://example.com/callback*", True),  # Wildcard at the end
            ("https://example.com/callback", False),  # No wildcard
            ("https://example.com/call*back", False),  # Asterisk not at the end
            ("http://localhost/callback/*", True),  # Localhost with wildcard
            ("https://example.com/*", True),  # Wildcard directly after domain
            ("https://example.com/auth?*", True),  # Wildcard in GET parameters
            ("http://::1/auth?*", True),  # Wildcard in GET parameters
        ],
    )
    def test_redirect_uri_is_wildcard_uri(self, auditor, redirect_uri, should_alert):
        assert auditor.redirect_uri_is_wildcard_uri(redirect_uri) == should_alert

    def test_audit_function_no_findings(self, mock_client, auditor):
        mock_client.get_resolved_redirect_uris.return_value = [
            "https://example.com/callback",
            "https://another.com/path",
        ]
        auditor._DB.get_all_clients.return_value = [mock_client]
        results = list(auditor.audit())
        assert len(results) == 0

    def test_audit_function_with_findings(self, mock_client, auditor):
        mock_client.get_resolved_redirect_uris.return_value = [
            "https://example.com/callback*",
            "https://valid.com/path",
        ]
        auditor._DB.get_all_clients.return_value = [mock_client]
        results = list(auditor.audit())
        assert len(results) == 1
        finding = results[0]
        assert (
            "redirect_uri" in finding.to_dict()["additional_details"]
            and finding.to_dict()["additional_details"]["redirect_uri"] == "https://example.com/callback*"
        )

    def test_audit_function_multiple_clients(self, mock_client, auditor):
        # Setting up various redirect URI configurations
        mock_client.get_resolved_redirect_uris.side_effect = [
            ["https://secure.com/path", "https://example.com/callback"],
            ["https://bad.com/callback*", "https://also.bad.com/endswith*"],
        ]
        auditor._DB.get_all_clients.return_value = [mock_client, mock_client]
        results = list(auditor.audit())
        assert len(results) == 2  # Expect two findings from the second client
