import pytest
from unittest.mock import Mock

from kcwarden.auditors.idp.saml_idp_want_authn_requests_signed import (
    SamlIdpWantAuthnRequestsSignedCheck,
)
from kcwarden.custom_types import config_keys


class TestSamlIdpWantAuthnRequestsSignedCheck:
    @pytest.fixture
    def auditor(self, database, default_config):
        auditor_instance = SamlIdpWantAuthnRequestsSignedCheck(database, default_config)
        auditor_instance._DB = Mock()
        return auditor_instance

    @pytest.mark.parametrize(
        "provider_id, expected",
        [
            ("saml", True),  # SAML provider should be considered
            ("oidc", False),  # OIDC provider should not be considered
            ("keycloak-oidc", False),  # Keycloak OIDC provider should not be considered
            ("github", False),  # Social providers should not be considered
        ],
    )
    def test_should_consider_idp(self, auditor, provider_id, expected):
        mock_idp = Mock()
        mock_idp.get_provider_id.return_value = provider_id
        assert auditor.should_consider_idp(mock_idp) == expected

    @pytest.mark.parametrize(
        "config, expected",
        [
            ({"wantAuthnRequestsSigned": "true"}, False),  # Signed requests enabled (Safe)
            ({"wantAuthnRequestsSigned": "false"}, True),  # Signed requests disabled (Vulnerable)
            ({}, True),  # Config missing (Defaults to false in code -> Vulnerable)
            ({"wantAuthnRequestsSigned": "garbage"}, True),  # Invalid value (!= "true" -> Vulnerable)
        ],
    )
    def test_is_vulnerable(self, auditor, config, expected):
        # We simulate the IDP object just enough to return the config
        mock_idp = Mock()
        mock_idp.get_config.return_value = config
        assert auditor.is_vulnerable(mock_idp) == expected

    def test_audit_function_no_findings(self, auditor, mock_idp):
        # Setup SAML IDP with correct configuration
        mock_idp.get_provider_id.return_value = "saml"
        mock_idp.get_config.return_value = {"wantAuthnRequestsSigned": "true"}
        auditor._DB.get_all_identity_providers.return_value = [mock_idp]

        results = list(auditor.audit())
        assert len(results) == 0

    def test_audit_function_with_findings(self, auditor, mock_idp):
        # Setup SAML IDP with vulnerable configuration
        mock_idp.get_provider_id.return_value = "saml"
        mock_idp.get_config.return_value = {"wantAuthnRequestsSigned": "false"}
        auditor._DB.get_all_identity_providers.return_value = [mock_idp]

        results = list(auditor.audit())
        assert len(results) == 1

    def test_audit_function_with_findings_default_config(self, auditor, mock_idp):
        # Setup SAML IDP with missing configuration (should default to false/vulnerable)
        mock_idp.get_provider_id.return_value = "saml"
        mock_idp.get_config.return_value = {}
        auditor._DB.get_all_identity_providers.return_value = [mock_idp]

        results = list(auditor.audit())
        assert len(results) == 1

    def test_audit_function_multiple_idps(self, auditor):
        # Create separate mock IDPs with distinct settings
        idp1 = Mock()
        idp1.get_provider_id.return_value = "saml"
        idp1.get_config.return_value = {"wantAuthnRequestsSigned": "false"}  # Vulnerable

        idp2 = Mock()
        idp2.get_provider_id.return_value = "saml"
        idp2.get_config.return_value = {"wantAuthnRequestsSigned": "true"}   # Safe

        idp3 = Mock()
        idp3.get_provider_id.return_value = "oidc"
        idp3.get_config.return_value = {"wantAuthnRequestsSigned": "false"}  # Ignored (Wrong provider type)

        auditor._DB.get_all_identity_providers.return_value = [idp1, idp2, idp3]
        results = list(auditor.audit())
        assert len(results) == 1  # Expect findings only from idp1

    def test_ignore_list_functionality(self, auditor, mock_idp):
        # Setup IDP that is vulnerable but should be ignored
        mock_idp.get_provider_id.return_value = "saml"
        mock_idp.get_config.return_value = {"wantAuthnRequestsSigned": "false"}
        mock_idp.get_alias.return_value = "ignored_idp"
        mock_idp.get_name.return_value = mock_idp.get_alias.return_value
        auditor._DB.get_all_identity_providers.return_value = [mock_idp]

        # Add the IDP to the ignore list
        auditor._CONFIG = {config_keys.AUDITOR_CONFIG: {auditor.get_classname(): ["ignored_idp"]}}

        results = list(auditor.audit())
        assert len(results) == 0  # No findings due to ignore list