import pytest
from unittest.mock import Mock

from kcwarden.auditors.idp.oidc_identity_provider_without_pkce import OIDCIdentityProviderWithoutPKCE


class TestOIDCIdentityProviderWithoutPKCE:
    @pytest.fixture
    def auditor(self, database, default_config):
        auditor_instance = OIDCIdentityProviderWithoutPKCE(database, default_config)
        auditor_instance._DB = Mock()
        return auditor_instance

    @pytest.mark.parametrize(
        "provider_id, expected",
        [
            ("oidc", True),  # OIDC provider should be considered
            ("keycloak-oidc", True),  # Keycloak OIDC provider should be considered
            ("saml", False),  # SAML provider should not be considered
        ],
    )
    def test_should_consider_idp(self, auditor, provider_id, expected):
        mock_idp = Mock()
        mock_idp.get_provider_id.return_value = provider_id
        assert auditor.should_consider_idp(mock_idp) == expected

    @pytest.mark.parametrize(
        "config, expected",
        [
            ({"pkceEnabled": "true", "pkceMethod": "S256"}, False),  # Correctly configured PKCE
            ({"pkceEnabled": "false", "pkceMethod": "S256"}, True),  # PKCE disabled
            ({"pkceEnabled": "true", "pkceMethod": "plain"}, True),  # PKCE enabled, but with plain method
            ({}, True),  # No PKCE settings
            ({"pkceMethod": "S256"}, True),  # PKCE method set, but not enabled
        ],
    )
    def test_idp_does_not_enforce_pkce(self, auditor, config, expected):
        assert auditor.idp_does_not_enforce_pkce(config) == expected

    def test_audit_function_no_findings(self, auditor, mock_idp):
        # Setup IDP with correct PKCE configuration
        mock_idp.get_provider_id.return_value = "oidc"
        mock_idp.get_config.return_value = {"pkceEnabled": "true", "pkceMethod": "S256"}
        auditor._DB.get_all_identity_providers.return_value = [mock_idp]

        results = list(auditor.audit())
        assert len(results) == 0

    def test_audit_function_with_findings(self, auditor, mock_idp):
        # Setup IDP without correct PKCE configuration
        mock_idp.get_provider_id.return_value = "oidc"
        mock_idp.get_config.return_value = {"pkceEnabled": "false"}
        auditor._DB.get_all_identity_providers.return_value = [mock_idp]

        results = list(auditor.audit())
        assert len(results) == 1
        finding = results[0].to_dict()
        assert finding["additional_details"]["pkceEnabled"] == "false"
        assert finding["additional_details"]["pkceMethod"] == "[unset]"

    def test_audit_function_multiple_idps(self, auditor):
        # Create separate mock IDPs with distinct settings
        idp1 = Mock()
        idp1.get_provider_id.return_value = "oidc"
        idp1.get_config.return_value = {"pkceEnabled": "true", "pkceMethod": "S256"}

        idp2 = Mock()
        idp2.get_provider_id.return_value = "oidc"
        idp2.get_config.return_value = {"pkceEnabled": "false"}

        idp3 = Mock()
        idp3.get_provider_id.return_value = "keycloak-oidc"
        idp3.get_config.return_value = {"pkceMethod": "plain"}

        auditor._DB.get_all_identity_providers.return_value = [idp1, idp2, idp3]
        results = list(auditor.audit())
        assert len(results) == 2  # Expect findings from idp2 and idp3
