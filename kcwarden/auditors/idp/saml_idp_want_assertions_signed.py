from kcwarden.api import Auditor
from kcwarden.custom_types.result import Severity

class SamlIdpWantAssertionsSignedCheck(Auditor):
    DEFAULT_SEVERITY = Severity.High
    SHORT_DESCRIPTION = "SAML IdP 'Want Assertions Signed' is disabled"
    LONG_DESCRIPTION = "The Identity Provider does not require SAML Assertions to be signed. This may allow attackers to modify the assertion content (e.g., username/roles) even if the envelope signature is valid, or if used in conjunction with other flaws."
    REFERENCE = ""

    def should_consider_idp(self, idp) -> bool:
        return self.is_not_ignored(idp) and idp.is_saml_provider()

    def audit(self):
        for idp in self._DB.get_all_identity_providers():
            if self.should_consider_idp(idp):
                if not idp.is_want_assertions_signed():
                    yield self.generate_finding(idp)