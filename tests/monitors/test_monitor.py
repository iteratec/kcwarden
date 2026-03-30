import pytest

from kcwarden.api.monitor import Monitor
from kcwarden.monitors.client.client_with_sensitive_scope import ClientWithSensitiveScope


class TestMonitorNoteField:
    """Tests for the note field behavior in generate_finding_with_severity_from_config."""

    @pytest.fixture
    def monitor(self, mock_database, default_config):
        return ClientWithSensitiveScope(mock_database, default_config)

    @pytest.fixture
    def matched_config(self):
        return {"scope": "sensitive-scope", "allowed": []}

    def test_note_replaces_long_description(self, monitor, mock_client, matched_config):
        matched_config["note"] = "Custom note explaining why this is interesting"
        result = monitor.generate_finding_with_severity_from_config(mock_client, matched_config)
        assert result.long_description == "Custom note explaining why this is interesting"

    def test_no_note_uses_default_long_description(self, monitor, mock_client, matched_config):
        result = monitor.generate_finding_with_severity_from_config(mock_client, matched_config)
        assert result.long_description == ClientWithSensitiveScope.LONG_DESCRIPTION

    def test_placeholder_note_uses_default_long_description(self, monitor, mock_client, matched_config):
        matched_config["note"] = Monitor.COMMON_CUSTOM_CONFIG_TEMPLATE["note"]
        result = monitor.generate_finding_with_severity_from_config(mock_client, matched_config)
        assert result.long_description == ClientWithSensitiveScope.LONG_DESCRIPTION

    def test_override_long_description_takes_precedence_over_note(self, monitor, mock_client, matched_config):
        matched_config["note"] = "Custom note"
        result = monitor.generate_finding_with_severity_from_config(
            mock_client, matched_config, override_long_description="Explicit override"
        )
        assert result.long_description == "Explicit override"
