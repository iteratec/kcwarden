import pytest
from unittest.mock import Mock

from kcwarden.api.auditor import ClientAuditor
from kcwarden.custom_types.config_keys import AUDITOR_CONFIG
from kcwarden.custom_types.result import Severity


class ConcreteClientAuditor(ClientAuditor):
    DEFAULT_SEVERITY = Severity.Medium
    SHORT_DESCRIPTION = "test"
    LONG_DESCRIPTION = "test"
    REFERENCE = "test"

    def audit_client(self, client):
        yield from []


class TestClientAuditorShouldConsiderClient:
    @pytest.fixture
    def auditor(self, database, default_config):
        auditor_instance = ConcreteClientAuditor(database, default_config)
        auditor_instance.is_not_ignored = Mock(return_value=True)
        return auditor_instance

    def test_should_consider_normal_client(self, mock_client, auditor):
        mock_client.is_system_client.return_value = False
        assert auditor.should_consider_client(mock_client) is True

    def test_should_consider_system_client_returns_false(self, mock_client, auditor):
        # Keycloak internal _system client should always be skipped
        mock_client.is_system_client.return_value = True
        assert auditor.should_consider_client(mock_client) is False

    def test_should_consider_ignored_client_returns_false(self, mock_client, auditor):
        auditor.is_not_ignored.return_value = False
        mock_client.is_system_client.return_value = False
        assert auditor.should_consider_client(mock_client) is False


class TestClientAuditorIsNotIgnored:
    """Tests for the real is_not_ignored implementation (ignore list via config)."""

    @pytest.fixture
    def auditor_with_ignore_list(self, database):
        config = {AUDITOR_CONFIG: {"ConcreteClientAuditor": ["ignored-client", "ignored-regex-.*"]}}
        return ConcreteClientAuditor(database, config)

    @pytest.fixture
    def auditor_empty_ignore_list(self, database):
        config = {AUDITOR_CONFIG: {"ConcreteClientAuditor": []}}
        return ConcreteClientAuditor(database, config)

    def test_client_not_in_ignore_list_is_not_ignored(self, mock_client, auditor_empty_ignore_list):
        mock_client.get_name.return_value = "some-client"
        assert auditor_empty_ignore_list.should_consider_client(mock_client) is True

    def test_client_exact_match_in_ignore_list_is_ignored(self, mock_client, auditor_with_ignore_list):
        mock_client.get_name.return_value = "ignored-client"
        assert auditor_with_ignore_list.should_consider_client(mock_client) is False

    def test_client_regex_match_in_ignore_list_is_ignored(self, mock_client, auditor_with_ignore_list):
        mock_client.get_name.return_value = "ignored-regex-something"
        assert auditor_with_ignore_list.should_consider_client(mock_client) is False

    def test_client_unrelated_name_is_not_ignored(self, mock_client, auditor_with_ignore_list):
        mock_client.get_name.return_value = "regular-client"
        assert auditor_with_ignore_list.should_consider_client(mock_client) is True
