import pytest
from unittest.mock import Mock

# Adjust the import path below if your directory structure differs
from kcwarden.auditors.idp.saml_idp_validate_signature import (
    SamlIdpValidateSignatureCheck,
)
from kcwarden.custom_types import config_keys


class TestSamlIdpValidateSignatureCheck:
    @pytest.fixture
    def auditor(self, database, default_config):
        auditor_instance = SamlIdpValidateSignatureCheck(database, default_config)
        auditor_instance._DB = Mock()
        return auditor_instance

    @pytest.mark.parametrize(
        "provider_id, expected",
        [
            ("saml", True),  # SAML provider should be considered
            ("oidc", False),  # OIDC provider should not be considered
            ("keycloak-oidc", False),  # Keycloak OIDC provider should not be considered
            ("github", False),  # Social provider should not be considered
        ],
    )
    def test_should_consider_idp(self, auditor, provider_id, expected):
        mock_idp = Mock()
        mock_idp.get_provider_id.return_value = provider_id
        assert auditor.should_consider_idp(mock_idp) == expected

    @pytest.mark.parametrize(
        "config, expected",
        [
            ({"validateSignature": "true"}, False),  # Signature verification enabled (Not vulnerable)
            ({"validateSignature": "false"}, True),  # Signature verification disabled (Vulnerable)
            ({}, True),  # Setting missing defaults to false (Vulnerable)
            ({"validateSignature": "garbage"}, True), # Invalid setting is not "true" (Vulnerable)
        ],
    )
    def test_is_vulnerable(self, auditor, config, expected):
        mock_idp = Mock()
        mock_idp.get_config.return_value = config
        assert auditor.is_vulnerable(mock_idp) == expected

    def test_audit_function_no_findings(self, auditor, mock_idp):
        # Setup IDP with correct configuration
        mock_idp.get_provider_id.return_value = "saml"
        mock_idp.get_config.return_value = {"validateSignature": "true"}
        auditor._DB.get_all_identity_providers.return_value = [mock_idp]

        results = list(auditor.audit())
        assert len(results) == 0

    def test_audit_function_with_findings(self, auditor, mock_idp):
        # Setup IDP with vulnerable configuration
        mock_idp.get_provider_id.return_value = "saml"
        mock_idp.get_config.return_value = {"validateSignature": "false"}
        auditor._DB.get_all_identity_providers.return_value = [mock_idp]

        results = list(auditor.audit())
        assert len(results) == 1

    def test_audit_function_multiple_idps(self, auditor):
        # Create separate mock IDPs with distinct settings
        idp1 = Mock()
        idp1.get_provider_id.return_value = "saml"
        idp1.get_config.return_value = {"validateSignature": "false"}  # Vulnerable

        idp2 = Mock()
        idp2.get_provider_id.return_value = "saml"
        idp2.get_config.return_value = {"validateSignature": "true"}  # Secure

        idp3 = Mock()
        idp3.get_provider_id.return_value = "oidc"
        idp3.get_config.return_value = {"validateSignature": "false"}  # Vulnerable but not SAML

        auditor._DB.get_all_identity_providers.return_value = [idp1, idp2, idp3]
        results = list(auditor.audit())
        assert len(results) == 1  # Expect findings from idp1 only

    def test_ignore_list_functionality(self, auditor, mock_idp):
        # Setup IDP that is vulnerable but ignored
        mock_idp.get_provider_id.return_value = "saml"
        mock_idp.get_config.return_value = {"validateSignature": "false"}
        mock_idp.get_alias.return_value = "ignored_idp"
        mock_idp.get_name.return_value = mock_idp.get_alias.return_value
        auditor._DB.get_all_identity_providers.return_value = [mock_idp]

        # Add the IDP to the ignore list
        auditor._CONFIG = {config_keys.AUDITOR_CONFIG: {auditor.get_classname(): ["ignored_idp"]}}

        results = list(auditor.audit())
        assert len(results) == 0  # No findings due to ignore list