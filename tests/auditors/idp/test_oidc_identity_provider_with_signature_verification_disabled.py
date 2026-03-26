import pytest
from unittest.mock import Mock

from kcwarden.auditors.idp.identity_provider_with_signature_verification_disabled import (
    IdentityProviderWithSignatureVerificationDisabled,
)
from kcwarden.custom_types import config_keys


class TestOIDCIdentityProviderWithSignatureVerificationDisabled:
    @pytest.fixture
    def auditor(self, database, default_config):
        auditor_instance = IdentityProviderWithSignatureVerificationDisabled(database, default_config)
        auditor_instance._DB = Mock()
        return auditor_instance

    @pytest.mark.parametrize(
        "provider_id, expected",
        [
            ("oidc", True),  # OIDC provider should be considered
            ("keycloak-oidc", True),  # Keycloak OIDC provider should be considered
            ("saml", False),  # SAML provider is handled by SamlIdentityProviderWithSignatureVerificationDisabled
            ("github", False),  # Other providers should not be considered
        ],
    )
    def test_should_consider_idp(self, auditor, provider_id, expected):
        mock_idp = Mock()
        mock_idp.get_provider_id.return_value = provider_id
        assert auditor.should_consider_idp(mock_idp) == expected

    def test_audit_function_no_findings(self, auditor, mock_idp):
        mock_idp.get_provider_id.return_value = "oidc"
        mock_idp.is_signature_validation_enabled.return_value = True
        auditor._DB.get_all_identity_providers.return_value = [mock_idp]

        results = list(auditor.audit())
        assert len(results) == 0

    def test_audit_function_with_findings(self, auditor, mock_idp):
        mock_idp.get_provider_id.return_value = "oidc"
        mock_idp.is_signature_validation_enabled.return_value = False
        auditor._DB.get_all_identity_providers.return_value = [mock_idp]

        results = list(auditor.audit())
        assert len(results) == 1

    def test_audit_function_multiple_idps(self, auditor):
        # IDP 1: Vulnerable OIDC (Signature Validation Disabled)
        idp1 = Mock()
        idp1.get_provider_id.return_value = "oidc"
        idp1.is_signature_validation_enabled.return_value = False

        # IDP 2: Secure OIDC (Signature Validation Enabled)
        idp2 = Mock()
        idp2.get_provider_id.return_value = "oidc"
        idp2.is_signature_validation_enabled.return_value = True

        # IDP 3: Vulnerable Keycloak OIDC
        idp3 = Mock()
        idp3.get_provider_id.return_value = "keycloak-oidc"
        idp3.is_signature_validation_enabled.return_value = False

        # IDP 4: SAML (Should be ignored, handled by SamlIdentityProviderWithSignatureVerificationDisabled)
        idp4 = Mock()
        idp4.get_provider_id.return_value = "saml"
        idp4.is_signature_validation_enabled.return_value = False

        auditor._DB.get_all_identity_providers.return_value = [idp1, idp2, idp3, idp4]
        results = list(auditor.audit())
        assert (
            len(results) == 2
        )  # Expect findings from idp1 and idp3; idp4 (SAML) is handled by SamlIdentityProviderWithSignatureVerificationDisabled

    def test_ignore_list_functionality(self, auditor, mock_idp):
        mock_idp.get_provider_id.return_value = "oidc"
        mock_idp.is_signature_validation_enabled.return_value = False
        mock_idp.get_alias.return_value = "ignored_idp"
        mock_idp.get_name.return_value = mock_idp.get_alias.return_value
        auditor._DB.get_all_identity_providers.return_value = [mock_idp]

        # Add the IDP to the ignore list
        auditor._CONFIG = {config_keys.AUDITOR_CONFIG: {auditor.get_classname(): ["ignored_idp"]}}

        results = list(auditor.audit())
        assert len(results) == 0  # No findings due to ignore list
