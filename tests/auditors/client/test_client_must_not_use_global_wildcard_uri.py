import pytest
from unittest.mock import Mock

from kcwarden.auditors.client.client_must_not_use_global_wildcard_uri import ClientMustNotUseGlobalWildcardURI


class TestClientMustNotUseGlobalWildcardURI:
    @pytest.fixture
    def auditor(self, database, default_config):
        auditor_instance = ClientMustNotUseGlobalWildcardURI(database, default_config)
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
            ("*", True),  # Global wildcard
            ("https://*", True),  # Arbitrary https link as wildcard
            ("http://*", True),  # Arbitrary http link as wildcard
            ("tel://*", True),  # Arbitrary other protocol link as wildcard
            (
                "https://example.com*",
                False,
            ),  # Wildcard in domain part → caught by ClientHasErroneouslyConfiguredWildcardURI
            ("https://example.com/*", False),  # Wildcard at the end → caught by ClientShouldNotUseWildcardRedirectURI
            (
                "https://example.com/callback*",
                False,
            ),  # Wildcard at the end → caught by ClientShouldNotUseWildcardRedirectURI
            ("https://example.com/callback", False),  # No wildcard
        ],
    )
    def test_redirect_uri_is_global_wildcard(self, auditor, redirect_uri, should_alert):
        assert auditor.redirect_uri_is_global_wildcard(redirect_uri) == should_alert

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
            "*",
            "https://valid.com/path",
        ]
        mock_client.is_public.return_value = False
        auditor._DB.get_all_clients.return_value = [mock_client]
        results = list(auditor.audit())
        assert len(results) == 1
        finding = results[0]
        assert (
            "redirect_uri" in finding.to_dict()["additional_details"]
            and finding.to_dict()["additional_details"]["redirect_uri"] == "*"
        )

    def test_audit_function_multiple_clients(self, mock_client, auditor):
        # Setting up various redirect URI configurations
        mock_client.get_resolved_redirect_uris.side_effect = [
            ["https://secure.com/path", "https://example.com/callback"],
            ["*"],
            ["*"],
        ]
        auditor._DB.get_all_clients.return_value = [mock_client, mock_client, mock_client]
        results = list(auditor.audit())
        assert len(results) == 2  # Expect a finding from the second and third client
