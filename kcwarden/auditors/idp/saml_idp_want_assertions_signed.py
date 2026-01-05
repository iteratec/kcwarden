from kcwarden.api import Auditor
from kcwarden.custom_types.result import Severity

class SamlIdpWantAssertionsSignedCheck(Auditor):
    DEFAULT_SEVERITY = Severity.High
    SHORT_DESCRIPTION = "SAML IdP 'Want Assertions Signed' is disabled"
    LONG_DESCRIPTION = "The Identity Provider does not require SAML Assertions to be signed. This may allow attackers to modify the assertion content (e.g., username/roles) even if the envelope signature is valid, or if used in conjunction with other flaws."
    REFERENCE = ""

    def should_consider_idp(self, idp) -> bool:
        return self.is_not_ignored(idp) and idp.get_provider_id() == "saml"

    def is_vulnerable(self, idp) -> bool:
        config = idp.get_config()
        val = config.get("wantAssertionsSigned", "false")
        return val != "true"

    def audit(self):
        for idp in self._DB.get_all_identity_providers():
            if not self.should_consider_idp(idp):
                continue
            if not self.is_vulnerable(idp):
                continue  
            yield self.generate_finding(idp)