from kcwarden.auditors.client.public_client_should_disable_direct_access_grants import (
    PublicClientShouldDisableDirectAccessGrants,
)


import pytest


from unittest.mock import Mock


class TestPublicClientShouldDisableDirectAccessGrants:
    @pytest.fixture
    def auditor(self, database, default_config):
        auditor_instance = PublicClientShouldDisableDirectAccessGrants(database, default_config)
        auditor_instance._DB = Mock()  # Mocking the database interactions
        return auditor_instance

    @pytest.mark.parametrize(
        "is_oidc,is_public,expected",
        [
            (True, True, True),  # Public OIDC client should be considered
            (False, True, False),  # Non-OIDC public client should not be considered
            (True, False, False),  # OIDC but confidential client should not be considered
        ],
    )
    def test_client_consideration_logic(self, mock_client, auditor, is_oidc, is_public, expected):
        mock_client.is_oidc_client.return_value = is_oidc
        mock_client.is_public.return_value = is_public
        assert (
            auditor.should_consider_client(mock_client) == expected
        ), "Client consideration logic failed based on type and OIDC status"

    @pytest.mark.parametrize(
        "has_direct_access_grants,expected",
        [
            (True, True),  # Client with direct access grants should be detected
            (False, False),  # Client without direct access grants should not be detected
        ],
    )
    def test_detect_direct_access_grants(self, public_client, auditor, has_direct_access_grants, expected):
        public_client.has_direct_access_grants_enabled.return_value = has_direct_access_grants
        assert (
            auditor.client_uses_direct_access_grants(public_client) == expected
        ), "Direct access grants detection logic failed"

    @pytest.mark.parametrize(
        "enable_direct_access_grants,expected_count",
        [
            (True, 1),  # Client using direct access grants should result in a finding
            (False, 0),  # Client not using direct access grants should result in no findings
        ],
    )
    def test_audit_function_with_single_client(
        self, public_client, auditor, enable_direct_access_grants, expected_count
    ):
        public_client.is_oidc_client.return_value = True
        public_client.has_direct_access_grants_enabled.return_value = enable_direct_access_grants
        auditor._DB.get_all_clients.return_value = [public_client]
        results = list(auditor.audit())
        assert len(results) == expected_count, "Audit findings count mismatch for single client"

    def test_audit_function_with_multiple_clients(self, public_client, auditor):
        public_client.is_oidc_client.return_value = True
        public_client.has_direct_access_grants_enabled.side_effect = [
            True,
            False,
            True,
        ]  # Varying setups among three clients
        auditor._DB.get_all_clients.return_value = [public_client, public_client, public_client]
        results = list(auditor.audit())
        assert len(results) == 2, "Audit did not yield correct number of findings for multiple clients"
