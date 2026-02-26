from kcwarden.api import Auditor
from kcwarden.custom_types.result import Severity

class SamlIdpValidateSignatureCheck(Auditor):
    DEFAULT_SEVERITY = Severity.High
    SHORT_DESCRIPTION = "SAML IdP 'Validate Signature' is disabled"
    LONG_DESCRIPTION = "The Identity Provider is configured with 'validateSignature' set to false. Keycloak will not verify the digital signature of incoming SAML documents, allowing for token forgery."
    REFERENCE = ""

    def should_consider_idp(self, idp) -> bool:
        return self.is_not_ignored(idp) and idp.is_saml_provider()

    def audit(self):
        for idp in self._DB.get_all_identity_providers():
            if self.should_consider_idp(idp):
                if not idp.is_signature_validation_enabled():
                    yield self.generate_finding(idp)