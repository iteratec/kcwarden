from kcwarden.api import Auditor
from kcwarden.custom_types.result import Severity

class SamlIdpWantAssertionsEncryptedCheck(Auditor):
    DEFAULT_SEVERITY = Severity.Medium
    SHORT_DESCRIPTION = "SAML IdP 'Want Assertions Encrypted' is disabled"
    LONG_DESCRIPTION = "The Identity Provider accepts unencrypted assertions. This exposes PII to intermediaries and makes the system more susceptible to XML Signature Wrapping (XSW) attacks."
    REFERENCE = ""

    def should_consider_idp(self, idp) -> bool:
        return self.is_not_ignored(idp) and idp.is_saml_provider()

    def audit(self):
        for idp in self._DB.get_all_identity_providers():
            if self.should_consider_idp(idp):
                if not idp.is_want_assertions_encrypted():
                    yield self.generate_finding(idp)