import unittest.mock

import pytest

from kcwarden.auditors.client.client_has_no_redirect_uris import ClientHasNoRedirectUris
from kcwarden.custom_types.database import Database
from kcwarden.custom_types.keycloak_object import Client


class TestClientHasNoRedirectUris:
    @pytest.fixture
    def auditor(self, database, default_config):
        auditor_instance = ClientHasNoRedirectUris(database, default_config)
        auditor_instance._DB = unittest.mock.create_autospec(spec=Database, instance=True)
        return auditor_instance

    @pytest.mark.parametrize(
        "is_oidc,has_standard_flow,has_implicit_flow,is_default_keycloak_client,expected",
        [
            (True, True, False, False, True),  # OIDC with standard flow
            (True, False, True, False, True),  # OIDC with implicit flow
            (False, True, True, False, False),  # Non-OIDC should be excluded
            (True, False, False, False, False),  # OIDC but no relevant flows
            (True, True, False, True, False),  # OIDC with standard flow but a default client
        ],
    )
    def test_should_consider_client(
        self,
        mock_client: Client,
        auditor: ClientHasNoRedirectUris,
        is_oidc: bool,
        has_standard_flow: bool,
        has_implicit_flow: bool,
        is_default_keycloak_client: bool,
        expected: bool,
    ):
        mock_client.is_oidc_client.return_value = is_oidc
        mock_client.has_standard_flow_enabled.return_value = has_standard_flow
        mock_client.has_implicit_flow_enabled.return_value = has_implicit_flow
        mock_client.is_default_keycloak_client.return_value = is_default_keycloak_client
        assert auditor.should_consider_client(mock_client) == expected

    def test_audit__expect_one_finding(self, mock_client, auditor):
        mock_client.has_standard_flow_enabled.return_value = True
        mock_client.get_resolved_redirect_uris.return_value = []
        auditor._DB.get_all_clients.return_value = [mock_client]
        results = list(auditor.audit())
        assert len(results) == 1

    def test_audit__expect_no_findings(self, mock_client: Client, auditor):
        mock_client.has_standard_flow_enabled.return_value = True
        mock_client.get_resolved_redirect_uris.return_value = [
            "https://example.com/callback",
        ]
        auditor._DB.get_all_clients.return_value = [mock_client]
        results = list(auditor.audit())
        assert len(results) == 0
