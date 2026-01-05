from kcwarden.api import Auditor
from kcwarden.custom_types.result import Severity

class SamlIdpWantAuthnRequestsSignedCheck(Auditor):
    DEFAULT_SEVERITY = Severity.Medium
    SHORT_DESCRIPTION = "SAML IdP 'Want AuthnRequests Signed' is disabled"
    LONG_DESCRIPTION = "Keycloak is sending authentication requests to the Identity Provider without a signature. The IdP treats these requests as anonymous, increasing the risk of IdP Confusion attacks and Login CSRF."
    REFERENCE = ""

    def should_consider_idp(self, idp) -> bool:
        return self.is_not_ignored(idp) and idp.get_provider_id() == "saml"

    def is_vulnerable(self, idp) -> bool:
        config = idp.get_config()
        val = config.get("wantAuthnRequestsSigned", "false")
        return val != "true"

    def audit(self):
        for idp in self._DB.get_all_identity_providers():
            if not self.should_consider_idp(idp):
                continue
            if not self.is_vulnerable(idp):
                continue  
            yield self.generate_finding(idp)