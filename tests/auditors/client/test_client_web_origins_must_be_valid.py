import pytest
from unittest.mock import Mock

from kcwarden.auditors.client.client_web_origins_must_be_valid import ClientWebOriginsMustBeValid
from kcwarden.custom_types.result import Severity


class TestClientWebOriginsMustBeValid:
    @pytest.fixture
    def auditor(self, database, default_config):
        instance = ClientWebOriginsMustBeValid(database, default_config)
        instance._DB = Mock()
        return instance

    # --- is_valid_origin ---

    @pytest.mark.parametrize(
        "origin",
        [
            "https://example.com",
            "https://example.com:8443",
            "http://localhost",
            "http://localhost:3000",
            "http://127.0.0.1",
            "http://127.0.0.1:8080",
            "+",
            "*",
            "",  # empty string (treated as "no value")
        ],
    )
    def test_valid_origins_are_accepted(self, origin):
        assert ClientWebOriginsMustBeValid.is_valid_origin(origin) is True

    @pytest.mark.parametrize(
        "origin",
        [
            "https://example.com/",  # trailing slash (non-empty path)
            "https://example.com/path",  # path component
            "https://example.com?foo=bar",  # query string
            "https://example.com#anchor",  # fragment
            "not-a-url",  # no scheme, no host
            "https://",  # scheme but no host
            "/*",  # Keycloak redirect URI wildcard, not a valid origin
        ],
    )
    def test_invalid_origins_are_rejected(self, origin):
        assert ClientWebOriginsMustBeValid.is_valid_origin(origin) is False

    # --- audit_client ---

    def test_no_finding_when_web_origins_empty(self, mock_client, auditor):
        mock_client.get_web_origins.return_value = []
        results = list(auditor.audit_client(mock_client))
        assert results == []

    def test_no_finding_for_valid_origin(self, mock_client, auditor):
        mock_client.get_web_origins.return_value = ["https://example.com"]
        results = list(auditor.audit_client(mock_client))
        assert results == []

    def test_no_finding_for_plus_special_value(self, mock_client, auditor):
        mock_client.get_web_origins.return_value = ["+"]
        results = list(auditor.audit_client(mock_client))
        assert results == []

    def test_no_finding_for_wildcard_special_value(self, mock_client, auditor):
        mock_client.get_web_origins.return_value = ["*"]
        results = list(auditor.audit_client(mock_client))
        assert results == []

    def test_finding_for_origin_with_path(self, mock_client, auditor):
        mock_client.get_web_origins.return_value = ["https://example.com/path"]
        results = list(auditor.audit_client(mock_client))
        assert len(results) == 1
        assert results[0].severity == Severity.Info
        assert results[0].additional_details["web_origin"] == "https://example.com/path"

    def test_finding_for_origin_with_trailing_slash(self, mock_client, auditor):
        mock_client.get_web_origins.return_value = ["https://example.com/"]
        results = list(auditor.audit_client(mock_client))
        assert len(results) == 1

    def test_one_finding_per_invalid_origin(self, mock_client, auditor):
        mock_client.get_web_origins.return_value = [
            "https://valid.com",
            "https://invalid.com/path",
            "not-a-url",
        ]
        results = list(auditor.audit_client(mock_client))
        assert len(results) == 2

    def test_audit_iterates_all_clients(self, mock_client, auditor):
        mock_client.get_web_origins.return_value = ["https://bad.com/oops"]
        auditor._DB.get_all_clients.return_value = [mock_client, mock_client]
        results = list(auditor.audit())
        assert len(results) == 2
