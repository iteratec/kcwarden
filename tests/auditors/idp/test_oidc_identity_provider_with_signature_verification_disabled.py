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
            ("saml", True),  # SAML provider should also be considered
            ("github", False),  # SAML provider should also be considered
        ],
    )
    def test_should_consider_idp(self, auditor, provider_id, expected):
        mock_idp = Mock()
        mock_idp.get_provider_id.return_value = provider_id
        assert auditor.should_consider_idp(mock_idp) == expected

    @pytest.mark.parametrize(
        "config, expected",
        [
            ({"validateSignature": "true"}, False),  # Signature verification enabled
            ({"validateSignature": "false"}, True),  # Signature verification disabled
        ],
    )
    def test_idp_does_not_enforce_pkce(self, auditor, config, expected):
        assert auditor.idp_does_not_verify_signatures(config) == expected

    def test_audit_function_no_findings(self, auditor, mock_idp):
        # Setup IDP with correct PKCE configuration
        mock_idp.get_provider_id.return_value = "oidc"
        mock_idp.get_config.return_value = {"validateSignature": "true"}
        auditor._DB.get_all_identity_providers.return_value = [mock_idp]

        results = list(auditor.audit())
        assert len(results) == 0

    def test_audit_function_with_findings(self, auditor, mock_idp):
        # Setup IDP without correct PKCE configuration
        mock_idp.get_provider_id.return_value = "oidc"
        mock_idp.get_config.return_value = {"validateSignature": "false"}
        auditor._DB.get_all_identity_providers.return_value = [mock_idp]

        results = list(auditor.audit())
        assert len(results) == 1

    def test_audit_function_multiple_idps(self, auditor):
        # Create separate mock IDPs with distinct settings
        idp1 = Mock()
        idp1.get_provider_id.return_value = "oidc"
        idp1.get_config.return_value = {"validateSignature": "false"}

        idp2 = Mock()
        idp2.get_provider_id.return_value = "oidc"
        idp2.get_config.return_value = {"validateSignature": "true"}

        idp3 = Mock()
        idp3.get_provider_id.return_value = "keycloak-oidc"
        idp3.get_config.return_value = {"validateSignature": "false"}

        idp4 = Mock()
        idp4.get_provider_id.return_value = "saml"
        idp4.get_config.return_value = {"validateSignature": "false"}

        auditor._DB.get_all_identity_providers.return_value = [idp1, idp2, idp3, idp4]
        results = list(auditor.audit())
        assert len(results) == 3  # Expect findings from idp1, idp3 and idp4

    def test_ignore_list_functionality(self, auditor, mock_idp):
        # Setup IDP without force sync mode and with mappers
        # Setup IDP without correct PKCE configuration
        mock_idp.get_provider_id.return_value = "oidc"
        mock_idp.get_config.return_value = {"validateSignature": "false"}
        mock_idp.get_alias.return_value = "ignored_idp"
        mock_idp.get_name.return_value = mock_idp.get_alias.return_value
        auditor._DB.get_all_identity_providers.return_value = [mock_idp]

        # Add the IDP to the ignore list
        auditor._CONFIG = {config_keys.AUDITOR_CONFIG: {auditor.get_classname(): ["ignored_idp"]}}

        results = list(auditor.audit())
        assert len(results) == 0  # No findings due to ignore list
