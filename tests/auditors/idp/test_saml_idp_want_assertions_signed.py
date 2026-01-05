import pytest
from unittest.mock import Mock

# Adjust the import path below to match where your file is actually located within your project structure
# e.g., from kcwarden.auditors.idp.saml_idp_want_assertions_signed import SamlIdpWantAssertionsSignedCheck
from kcwarden.auditors.idp.saml_idp_want_assertions_signed import SamlIdpWantAssertionsSignedCheck
from kcwarden.custom_types import config_keys


class TestSamlIdpWantAssertionsSignedCheck:
    @pytest.fixture
    def auditor(self, database, default_config):
        auditor_instance = SamlIdpWantAssertionsSignedCheck(database, default_config)
        auditor_instance._DB = Mock()
        return auditor_instance

    @pytest.mark.parametrize(
        "provider_id, expected",
        [
            ("saml", True),  # SAML provider should be considered
            ("oidc", False),  # OIDC provider should not be considered
            ("keycloak-oidc", False),  # Keycloak OIDC provider should not be considered
            ("github", False),  # Github provider should not be considered
        ],
    )
    def test_should_consider_idp(self, auditor, provider_id, expected):
        mock_idp = Mock()
        mock_idp.get_provider_id.return_value = provider_id
        assert auditor.should_consider_idp(mock_idp) == expected

    @pytest.mark.parametrize(
        "config, expected",
        [
            ({"wantAssertionsSigned": "true"}, False),  # Signed assertions required -> Not vulnerable
            ({"wantAssertionsSigned": "false"}, True),  # Signed assertions not required -> Vulnerable
            ({}, True),  # Config missing (defaults to false) -> Vulnerable
            ({"wantAssertionsSigned": "garbage"}, True),  # Invalid value (defaults to false logic) -> Vulnerable
        ],
    )
    def test_is_vulnerable(self, auditor, config, expected):
        mock_idp = Mock()
        mock_idp.get_config.return_value = config
        assert auditor.is_vulnerable(mock_idp) == expected

    def test_audit_function_no_findings(self, auditor, mock_idp):
        # Setup SAML IDP with signed assertions enabled
        mock_idp.get_provider_id.return_value = "saml"
        mock_idp.get_config.return_value = {"wantAssertionsSigned": "true"}
        auditor._DB.get_all_identity_providers.return_value = [mock_idp]

        results = list(auditor.audit())
        assert len(results) == 0

    def test_audit_function_with_findings(self, auditor, mock_idp):
        # Setup SAML IDP with signed assertions disabled
        mock_idp.get_provider_id.return_value = "saml"
        mock_idp.get_config.return_value = {"wantAssertionsSigned": "false"}
        auditor._DB.get_all_identity_providers.return_value = [mock_idp]

        results = list(auditor.audit())
        assert len(results) == 1

    def test_audit_function_multiple_idps(self, auditor):
        # Create separate mock IDPs with distinct settings
        
        # IDP 1: SAML, Vulnerable (false)
        idp1 = Mock()
        idp1.get_provider_id.return_value = "saml"
        idp1.get_config.return_value = {"wantAssertionsSigned": "false"}

        # IDP 2: SAML, Secure (true)
        idp2 = Mock()
        idp2.get_provider_id.return_value = "saml"
        idp2.get_config.return_value = {"wantAssertionsSigned": "true"}

        # IDP 3: OIDC, Vulnerable config (but should be ignored by provider type)
        idp3 = Mock()
        idp3.get_provider_id.return_value = "oidc"
        idp3.get_config.return_value = {"wantAssertionsSigned": "false"}

        # IDP 4: SAML, Vulnerable (missing config)
        idp4 = Mock()
        idp4.get_provider_id.return_value = "saml"
        idp4.get_config.return_value = {}

        auditor._DB.get_all_identity_providers.return_value = [idp1, idp2, idp3, idp4]
        results = list(auditor.audit())
        
        # Expect findings from idp1 and idp4 only
        assert len(results) == 2

    def test_ignore_list_functionality(self, auditor, mock_idp):
        # Setup Vulnerable SAML IDP
        mock_idp.get_provider_id.return_value = "saml"
        mock_idp.get_config.return_value = {"wantAssertionsSigned": "false"}
        
        mock_idp.get_alias.return_value = "ignored_idp"
        mock_idp.get_name.return_value = mock_idp.get_alias.return_value
        auditor._DB.get_all_identity_providers.return_value = [mock_idp]

        # Add the IDP to the ignore list
        auditor._CONFIG = {config_keys.AUDITOR_CONFIG: {auditor.get_classname(): ["ignored_idp"]}}

        results = list(auditor.audit())
        assert len(results) == 0  # No findings due to ignore list