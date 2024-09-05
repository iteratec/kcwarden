import pytest
from unittest.mock import Mock

from kcwarden.auditors.client.client_has_erroneously_configured_wildcard_uri import (
    ClientHasErroneouslyConfiguredWildcardURI,
)


class TestClientHasErroneouslyConfiguredWildcardURI:
    @pytest.fixture
    def auditor(self, database, default_config):
        auditor_instance = ClientHasErroneouslyConfiguredWildcardURI(database, default_config)
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
            ("https://example.com*", True),  # Wildcard in domain part
            ("https://example.com/*", False),  # Wildcard correctly in path
            ("https://example.com/subpath*", False),  # Wildcard correctly in path
            ("https://example.com/subpath/login?*", False),  # Wildcard in GET Parameters
            ("http://example.com*", True),  # Wildcard in domain part with http
            ("", False),  # Empty URI
            ("https://example.com", False),  # No wildcard
            ("https://*", True),  # Edge case: entire domain as wildcard
            ("*", True),  # Edge case: Only wildcard without protocol
        ],
    )
    def test_redirect_uri_has_wildcard_in_domain(self, auditor, redirect_uri, should_alert):
        assert auditor.redirect_uri_has_wildcard_in_domain(redirect_uri) == should_alert

    def test_audit_function_no_findings(self, mock_client, auditor):
        mock_client.get_resolved_redirect_uris.return_value = ["https://example.com/path", "https://example.com/other"]
        auditor._DB.get_all_clients.return_value = [mock_client]
        results = list(auditor.audit())
        assert len(results) == 0

    def test_audit_function_with_findings(self, mock_client, auditor):
        mock_client.get_resolved_redirect_uris.return_value = ["https://example.com*", "https://valid.com/path"]
        auditor._DB.get_all_clients.return_value = [mock_client]
        results = list(auditor.audit())
        assert len(results) == 1
        finding = results[0]
        assert finding.to_dict()["additional_details"]["redirect_uri"] == "https://example.com*"

    def test_audit_function_multiple_clients(self, mock_client, auditor):
        # Setting up various redirect URI configurations
        mock_client.get_resolved_redirect_uris.side_effect = [
            ["https://example.com*", "https://valid.com/path"],
            ["https://secure.com/path"],
            ["https://anotherbad.com*"],
        ]
        auditor._DB.get_all_clients.return_value = [mock_client, mock_client, mock_client]
        results = list(auditor.audit())
        assert len(results) == 2  # Expect findings from two clients
