import pytest
from unittest.mock import Mock

from kcwarden.auditors.idp.identity_provider_with_mappers_without_force_sync_mode import (
    IdentityProviderWithMappersWithoutForceSyncMode,
)
from kcwarden.custom_types import config_keys


class TestIdentityProviderWithMappersWithoutForceSyncMode:
    @pytest.fixture
    def auditor(self, database, default_config):
        auditor_instance = IdentityProviderWithMappersWithoutForceSyncMode(database, default_config)
        auditor_instance._DB = Mock()
        return auditor_instance

    def test_should_consider_idp(self, mock_idp, auditor):
        assert auditor.should_consider_idp(mock_idp) is True  # Always consider unless ignored

    @pytest.mark.parametrize(
        "sync_mode, expected",
        [
            ("FORCE", True),  # Force sync mode
            ("INHERIT", False),  # Inherit sync mode
            ("LEGACY", False),  # Legacy sync mode
        ],
    )
    def test_idp_uses_sync_mode_force(self, auditor, sync_mode, expected):
        mock_idp = Mock()
        mock_idp.get_sync_mode.return_value = sync_mode
        assert auditor.idp_uses_sync_mode_force(mock_idp) == expected

    @pytest.mark.parametrize(
        "mappers, expected",
        [
            ([{"name": "mapper1"}, {"name": "mapper2"}], True),  # IDP has mappers
            ([], False),  # IDP does not have mappers
        ],
    )
    def test_idp_uses_information_from_access_token(self, auditor, mappers, expected):
        mock_idp = Mock()
        mock_idp.get_identity_provider_mappers.return_value = mappers
        assert auditor.idp_uses_information_from_access_token(mock_idp) == expected

    def test_audit_function_no_findings(self, auditor, mock_idp):
        # Setup IDP with force sync mode and mappers
        mock_idp.get_sync_mode.return_value = "FORCE"
        mock_idp.get_identity_provider_mappers.return_value = [{"name": "mapper1"}]
        auditor._DB.get_all_identity_providers.return_value = [mock_idp]

        results = list(auditor.audit())
        assert len(results) == 0

    def test_audit_function_with_findings(self, auditor, mock_idp):
        # Setup IDP without force sync mode and with mappers
        mock_idp.get_sync_mode.return_value = "INHERIT"
        mock_idp.get_identity_provider_mappers.return_value = [{"name": "mapper1"}]
        auditor._DB.get_all_identity_providers.return_value = [mock_idp]

        results = list(auditor.audit())
        assert len(results) == 1

    def test_audit_function_multiple_idps(self, auditor):
        # Create separate mock IDPs with distinct settings
        idp1 = Mock()
        idp1.get_sync_mode.return_value = "INHERIT"
        idp1.get_identity_provider_mappers.return_value = [{"name": "mapper1"}]

        idp2 = Mock()
        idp2.get_sync_mode.return_value = "FORCE"
        idp2.get_identity_provider_mappers.return_value = [{"name": "mapper2"}]

        idp3 = Mock()
        idp3.get_sync_mode.return_value = "LEGACY"
        idp3.get_identity_provider_mappers.return_value = []

        auditor._DB.get_all_identity_providers.return_value = [idp1, idp2, idp3]
        results = list(auditor.audit())
        assert len(results) == 1  # Expect findings from idp1 only

    def test_ignore_list_functionality(self, auditor, mock_idp):
        # Setup IDP without force sync mode and with mappers
        mock_idp.get_sync_mode.return_value = "INHERIT"
        mock_idp.get_identity_provider_mappers.return_value = [{"name": "mapper1"}]
        mock_idp.get_alias.return_value = "ignored_idp"
        mock_idp.get_name.return_value = mock_idp.get_alias.return_value
        auditor._DB.get_all_identity_providers.return_value = [mock_idp]

        # Add the IDP to the ignore list
        auditor._CONFIG = {config_keys.AUDITOR_CONFIG: {auditor.get_classname(): ["ignored_idp"]}}

        results = list(auditor.audit())
        assert len(results) == 0  # No findings due to ignore list
