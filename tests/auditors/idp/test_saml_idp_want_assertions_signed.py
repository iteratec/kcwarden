import pytest
from unittest.mock import Mock

from kcwarden.auditors.idp.saml_idp_want_assertions_signed import SamlIdpWantAssertionsSignedCheck
from kcwarden.custom_types import config_keys


class TestSamlIdpWantAssertionsSignedCheck:
    @pytest.fixture
    def auditor(self, database, default_config):
        auditor_instance = SamlIdpWantAssertionsSignedCheck(database, default_config)
        auditor_instance._DB = Mock()
        return auditor_instance

    @pytest.mark.parametrize(
        "is_saml, expected",
        [
            (True, True),   # SAML provider should be considered
            (False, False), # Non-SAML provider should not be considered
        ],
    )
    def test_should_consider_idp(self, auditor, is_saml, expected):
        mock_idp = Mock()
        mock_idp.is_saml_provider.return_value = is_saml
        assert auditor.should_consider_idp(mock_idp) == expected

    def test_audit_function_no_findings(self, auditor):
        mock_idp = Mock()
        # Setup SAML IDP: Signed Assertions Enabled (Secure)
        mock_idp.is_saml_provider.return_value = True
        mock_idp.is_want_assertions_signed.return_value = True
        
        auditor._DB.get_all_identity_providers.return_value = [mock_idp]

        results = list(auditor.audit())
        assert len(results) == 0

    def test_audit_function_with_findings(self, auditor):
        mock_idp = Mock()
        # Setup SAML IDP: Signed Assertions Disabled (Vulnerable)
        mock_idp.is_saml_provider.return_value = True
        mock_idp.is_want_assertions_signed.return_value = False
        
        auditor._DB.get_all_identity_providers.return_value = [mock_idp]

        results = list(auditor.audit())
        assert len(results) == 1

    def test_audit_function_multiple_idps(self, auditor):
        # IDP 1: SAML, Vulnerable (false)
        idp1 = Mock()
        idp1.is_saml_provider.return_value = True
        idp1.is_want_assertions_signed.return_value = False

        # IDP 2: SAML, Secure (true)
        idp2 = Mock()
        idp2.is_saml_provider.return_value = True
        idp2.is_want_assertions_signed.return_value = True

        # IDP 3: OIDC, Vulnerable config (but should be ignored by provider type)
        idp3 = Mock()
        idp3.is_saml_provider.return_value = False
        idp3.is_want_assertions_signed.return_value = False

        # IDP 4: SAML, Vulnerable (simulating missing config logic handled by IDP class)
        idp4 = Mock()
        idp4.is_saml_provider.return_value = True
        idp4.is_want_assertions_signed.return_value = False

        auditor._DB.get_all_identity_providers.return_value = [idp1, idp2, idp3, idp4]
        results = list(auditor.audit())
        
        # Expect findings from idp1 and idp4 only
        assert len(results) == 2

    def test_ignore_list_functionality(self, auditor):
        mock_idp = Mock()
        # Setup Vulnerable SAML IDP
        mock_idp.is_saml_provider.return_value = True
        mock_idp.is_want_assertions_signed.return_value = False
        
        mock_idp.get_alias.return_value = "ignored_idp"
        mock_idp.get_name.return_value = "ignored_idp"
        
        auditor._DB.get_all_identity_providers.return_value = [mock_idp]

        # Add the IDP to the ignore list
        auditor._CONFIG = {
            config_keys.AUDITOR_CONFIG: {
                auditor.get_classname(): ["ignored_idp"]
            }
        }

        results = list(auditor.audit())
        assert len(results) == 0