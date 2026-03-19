import pytest
from unittest.mock import Mock

from kcwarden.auditors.client.client_web_origins_must_not_use_wildcard import ClientWebOriginsMustNotUseWildcard
from kcwarden.custom_types.result import Severity


class TestClientWebOriginsMustNotUseWildcard:
    @pytest.fixture
    def auditor(self, database, default_config):
        instance = ClientWebOriginsMustNotUseWildcard(database, default_config)
        instance._DB = Mock()
        return instance

    # --- should_consider_client ---

    @pytest.mark.parametrize(
        "is_oidc,expected",
        [
            (True, True),
            (False, False),
        ],
    )
    def test_should_consider_client(self, mock_client, auditor, is_oidc, expected):
        mock_client.is_oidc_client.return_value = is_oidc
        assert auditor.should_consider_client(mock_client) == expected

    # --- audit_client ---

    def test_no_finding_when_web_origins_empty(self, mock_client, auditor):
        mock_client.get_web_origins.return_value = []
        results = list(auditor.audit_client(mock_client))
        assert results == []

    def test_no_finding_for_valid_origin(self, mock_client, auditor):
        mock_client.get_web_origins.return_value = ["https://example.com"]
        results = list(auditor.audit_client(mock_client))
        assert results == []

    def test_no_finding_for_inherit_special_value(self, mock_client, auditor):
        mock_client.get_web_origins.return_value = ["+"]
        results = list(auditor.audit_client(mock_client))
        assert results == []

    def test_finding_for_wildcard(self, mock_client, auditor):
        mock_client.get_web_origins.return_value = ["*"]
        results = list(auditor.audit_client(mock_client))
        assert len(results) == 1
        assert results[0].severity == Severity.Medium

    def test_finding_for_wildcard_mixed_with_valid_origins(self, mock_client, auditor):
        mock_client.get_web_origins.return_value = ["https://example.com", "*"]
        results = list(auditor.audit_client(mock_client))
        assert len(results) == 1

    def test_audit_iterates_all_clients(self, mock_client, auditor):
        mock_client.get_web_origins.return_value = ["*"]
        auditor._DB.get_all_clients.return_value = [mock_client, mock_client]
        results = list(auditor.audit())
        assert len(results) == 2
