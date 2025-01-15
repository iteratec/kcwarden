from kcwarden.auditors.client.confidential_client_should_disable_direct_access_grants import (
    ConfidentialClientShouldDisableDirectAccessGrants,
)


import pytest


from unittest.mock import Mock


class TestConfidentialClientShouldDisableDirectAccessGrants:
    @pytest.fixture
    def auditor(self, database, default_config):
        auditor_instance = ConfidentialClientShouldDisableDirectAccessGrants(database, default_config)
        auditor_instance._DB = Mock()  # Mocking the database interactions
        return auditor_instance

    @pytest.mark.parametrize(
        "is_oidc,is_public,expected",
        [
            (True, False, True),  # Confidential OIDC client should be considered
            (True, True, False),  # Public clients should not be considered
            (False, False, False),  # Non-OIDC confidential clients should not be considered
        ],
    )
    def test_should_consider_client(self, mock_client, auditor, is_oidc, is_public, expected):
        mock_client.is_oidc_client.return_value = is_oidc
        mock_client.is_public.return_value = is_public
        assert auditor.should_consider_client(mock_client) == expected, (
            "Client consideration logic failed based on OIDC status and confidentiality"
        )

    @pytest.mark.parametrize(
        "has_direct_access_grants,expected",
        [
            (True, True),  # Clients with direct access grants should be detected
            (False, False),  # Clients without direct access grants should not be detected
        ],
    )
    def test_client_uses_direct_access_grants(self, confidential_client, auditor, has_direct_access_grants, expected):
        confidential_client.has_direct_access_grants_enabled.return_value = has_direct_access_grants
        assert auditor.client_uses_direct_access_grants(confidential_client) == expected, (
            "Direct access grants detection logic failed"
        )

    @pytest.mark.parametrize(
        "enable_direct_access_grants,expected_count",
        [
            (True, 1),  # Client using direct access grants should result in a finding
            (False, 0),  # Client not using direct access grants should result in no findings
        ],
    )
    def test_audit_function_with_single_client(
        self, confidential_client, auditor, enable_direct_access_grants, expected_count
    ):
        confidential_client.is_oidc_client.return_value = True
        confidential_client.has_direct_access_grants_enabled.return_value = enable_direct_access_grants
        auditor._DB.get_all_clients.return_value = [confidential_client]
        results = list(auditor.audit())
        assert len(results) == expected_count, "Audit findings count mismatch for single client"

    def test_audit_function_with_multiple_clients(self, confidential_client, auditor):
        confidential_client.is_oidc_client.return_value = True
        confidential_client.has_direct_access_grants_enabled.side_effect = [
            True,
            False,
            True,
        ]  # Varying setups among three clients
        auditor._DB.get_all_clients.return_value = [confidential_client, confidential_client, confidential_client]
        results = list(auditor.audit())
        assert len(results) == 2, "Audit did not yield correct number of findings for multiple clients"
