import pytest
from unittest.mock import Mock

from kcwarden.auditors.client.client_has_undefined_base_domain_and_schema_in_post_logout_redirect_uri import (
    ClientHasUndefinedBaseDomainAndSchemaInPostLogoutRedirectUri,
)
from kcwarden.custom_types.keycloak_object import Client, Realm


class TestClientHasUndefinedBaseDomainAndSchemaInPostLogoutRedirectUri:
    @pytest.fixture
    def auditor(self, database, default_config):
        instance = ClientHasUndefinedBaseDomainAndSchemaInPostLogoutRedirectUri(database, default_config)
        instance._DB = Mock()
        return instance

    # --- should_consider_client ---

    @pytest.mark.parametrize(
        "is_oidc,is_realm_specific,expected",
        [
            (True, False, True),  # standard OIDC client
            (False, False, False),  # non-OIDC client excluded
            (True, True, False),  # realm-specific client excluded
        ],
    )
    def test_should_consider_client(self, mock_client, auditor, is_oidc, is_realm_specific, expected):
        mock_client.is_oidc_client.return_value = is_oidc
        mock_client.is_realm_specific_client.return_value = is_realm_specific
        assert auditor.should_consider_client(mock_client) == expected

    # --- post_logout_redirect_uri_has_empty_scheme ---

    # noinspection HttpUrlsUsage
    @pytest.mark.parametrize(
        "uri,should_alert",
        [
            ("https://example.com/logout", False),  # fully qualified HTTPS
            ("http://example.com/logout", False),  # HTTP, defined scheme
            ("//example.com/logout", True),  # scheme-relative
            ("example.com/logout", True),  # no scheme at all
            ("/logout", True),  # root-relative (after resolution still no scheme)
        ],
    )
    def test_post_logout_redirect_uri_has_empty_scheme(self, auditor, uri, should_alert):
        assert auditor.post_logout_redirect_uri_has_empty_scheme(uri) == should_alert

    # --- audit_client ---

    def test_no_finding_when_post_logout_uris_empty(self, mock_client, auditor):
        mock_client.get_resolved_post_logout_redirect_uris.return_value = []
        results = list(auditor.audit_client(mock_client))
        assert results == []

    def test_no_finding_for_inherit_special_value(self, mock_client, auditor):
        mock_client.get_resolved_post_logout_redirect_uris.return_value = ["+"]
        results = list(auditor.audit_client(mock_client))
        assert results == []

    def test_no_finding_for_valid_uri(self, mock_client, auditor):
        mock_client.get_resolved_post_logout_redirect_uris.return_value = ["https://example.com/logout"]
        results = list(auditor.audit_client(mock_client))
        assert results == []

    def test_finding_for_scheme_relative_uri(self, mock_client, auditor):
        mock_client.get_resolved_post_logout_redirect_uris.return_value = ["//example.com/logout"]
        results = list(auditor.audit_client(mock_client))
        assert len(results) == 1
        assert results[0].additional_details["post_logout_redirect_uri"] == "//example.com/logout"

    def test_finding_for_uri_without_scheme(self, mock_client, auditor):
        mock_client.get_resolved_post_logout_redirect_uris.return_value = ["example.com/logout"]
        results = list(auditor.audit_client(mock_client))
        assert len(results) == 1

    def test_one_finding_per_invalid_uri(self, mock_client, auditor):
        mock_client.get_resolved_post_logout_redirect_uris.return_value = [
            "https://valid.com/logout",
            "//invalid.com/logout",
            "also-invalid.com/logout",
        ]
        results = list(auditor.audit_client(mock_client))
        assert len(results) == 2

    def test_inherit_value_mixed_with_invalid_uri(self, mock_client, auditor):
        mock_client.get_resolved_post_logout_redirect_uris.return_value = ["+", "//bad.com/logout"]
        results = list(auditor.audit_client(mock_client))
        assert len(results) == 1

    def test_audit_iterates_all_clients(self, mock_client, auditor):
        mock_client.get_resolved_post_logout_redirect_uris.return_value = ["//bad.com/logout"]
        auditor._DB.get_all_clients.return_value = [mock_client, mock_client]
        results = list(auditor.audit())
        assert len(results) == 2

    # --- get_post_logout_redirect_uris (data model) ---

    def test_get_post_logout_redirect_uris_parses_separator(self, example_db):
        # Verify that ## separation is parsed correctly via the data model
        realm = Mock(spec=Realm)
        realm.get_name.return_value = "test"
        client = Client(
            {
                "clientId": "test",
                "attributes": {"post.logout.redirect.uris": "https://a.com/logout##https://b.com/logout"},
            },
            [],
            {},
            realm,
        )
        assert client.get_post_logout_redirect_uris() == ["https://a.com/logout", "https://b.com/logout"]

    def test_get_post_logout_redirect_uris_empty_when_absent(self, example_db):
        realm = Mock(spec=Realm)
        realm.get_name.return_value = "test"
        client = Client(
            {
                "clientId": "test",
                "attributes": {},
            },
            [],
            {},
            realm,
        )
        assert client.get_post_logout_redirect_uris() == []
