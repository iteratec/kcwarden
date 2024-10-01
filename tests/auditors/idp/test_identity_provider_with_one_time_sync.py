import pytest
from unittest.mock import Mock

from kcwarden.auditors.idp.identity_provider_with_one_time_sync import IdentityProviderWithOneTimeSync
from kcwarden.custom_types import config_keys


class TestIdentityProviderWithOneTimeSync:
    @pytest.fixture
    def auditor(self, database, default_config):
        auditor_instance = IdentityProviderWithOneTimeSync(database, default_config)
        auditor_instance._DB = Mock()
        return auditor_instance

    def test_should_consider_idp(self, mock_idp, auditor):
        # Assuming the is_not_ignored function is simply a placeholder for actual implementation
        # Here it would typically check against a configuration setting or similar
        assert auditor.should_consider_idp(mock_idp) is True  # Always consider unless specifically ignored

    @pytest.mark.parametrize(
        "sync_mode, expected",
        [
            ("FORCE", False),  # IDP uses Force sync mode, should not generate a finding
            ("INHERIT", True),  # IDP uses Inherit sync mode, should generate a finding
            ("", True),  # IDP uses no specified sync mode, should generate a finding
        ],
    )
    def test_idp_does_not_use_force_sync_mode(self, auditor, sync_mode, expected):
        mock_idp = Mock()
        mock_idp.get_sync_mode.return_value = sync_mode
        assert auditor.idp_does_not_use_force_sync_mode(mock_idp) == expected

    def test_audit_function_no_findings(self, auditor, mock_idp):
        # Setup IDP with force sync mode
        mock_idp.get_sync_mode.return_value = "FORCE"
        auditor._DB.get_all_identity_providers.return_value = [mock_idp]

        results = list(auditor.audit())
        assert len(results) == 0

    def test_audit_function_with_findings(self, auditor, mock_idp):
        # Setup IDP without force sync mode
        mock_idp.get_sync_mode.return_value = "INHERIT"
        auditor._DB.get_all_identity_providers.return_value = [mock_idp]

        results = list(auditor.audit())
        assert len(results) == 1

    def test_audit_function_multiple_idps(self, auditor):
        # Create separate mock IDPs with distinct settings
        idp1 = Mock()
        idp1.get_sync_mode.return_value = "INHERIT"

        idp2 = Mock()
        idp2.get_sync_mode.return_value = "FORCE"

        idp3 = Mock()
        idp3.get_sync_mode.return_value = ""

        auditor._DB.get_all_identity_providers.return_value = [idp1, idp2, idp3]
        results = list(auditor.audit())
        assert len(results) == 2  # Expect findings from idp1 and idp3, but not from idp2

    def test_ignore_list_functionality(self, auditor, mock_idp):
        # Setup IDP without force sync mode and with mappers
        # Setup IDP without correct PKCE configuration
        mock_idp.get_sync_mode.return_value = "INHERIT"
        mock_idp.get_alias.return_value = "ignored_idp"
        mock_idp.get_name.return_value = mock_idp.get_alias.return_value
        auditor._DB.get_all_identity_providers.return_value = [mock_idp]

        # Add the IDP to the ignore list
        auditor._CONFIG = {
            config_keys.AUDITOR_CONFIG: {
                auditor.get_classname(): ["ignored_idp"]
            }
        }

        results = list(auditor.audit())
        assert len(results) == 0  # No findings due to ignore list
