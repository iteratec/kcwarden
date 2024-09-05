import pytest
from unittest.mock import Mock

from kcwarden.auditors.client.client_has_undefined_base_domain_and_schema import ClientHasUndefinedBaseDomainAndSchema


class TestClientHasUndefinedBaseDomainAndSchema:
    @pytest.fixture
    def auditor(self, database, default_config):
        auditor_instance = ClientHasUndefinedBaseDomainAndSchema(database, default_config)
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
            ("https://example.com/path", False),  # Properly defined scheme
            ("http://example.com/path", False),  # HTTP scheme, not secure but defined
            ("//example.com/path", True),  # Scheme-relative URL (undefined scheme)
            ("example.com/login", True),  # No scheme defined
        ],
    )
    def test_redirect_uri_has_empty_scheme(self, auditor, redirect_uri, should_alert):
        assert auditor.redirect_uri_has_empty_scheme(redirect_uri) == should_alert

    def test_audit_function_no_findings(self, mock_client, auditor):
        mock_client.get_resolved_redirect_uris.return_value = ["https://example.com/path", "http://localhost/login"]
        auditor._DB.get_all_clients.return_value = [mock_client]
        results = list(auditor.audit())
        assert len(results) == 0

    def test_audit_function_with_findings(self, mock_client, auditor):
        mock_client.get_resolved_redirect_uris.return_value = ["//example.com/login", "example.com/login"]
        auditor._DB.get_all_clients.return_value = [mock_client]
        results = list(auditor.audit())
        assert len(results) == 2  # Expect two finding for one client with all redirects problematic
        finding = results[0]
        assert "redirect_uri" in finding.to_dict()["additional_details"] and finding.to_dict()["additional_details"][
            "redirect_uri"
        ] in ["//example.com/login", "example.com/login"]

    def test_audit_function_multiple_clients(self, mock_client, auditor):
        # Setting up various redirect URI configurations
        mock_client.get_resolved_redirect_uris.side_effect = [
            ["https://example.com", "http://localhost"],
            ["//example.com/login", "example.com/login"],
        ]
        auditor._DB.get_all_clients.return_value = [mock_client, mock_client]
        results = list(auditor.audit())
        assert len(results) == 2  # Expect two findings from one client
