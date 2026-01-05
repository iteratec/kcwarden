from kcwarden.api import Auditor
from kcwarden.custom_types.result import Severity

class IdpWantAuthnRequestsSignedCheck(Auditor):
    DEFAULT_SEVERITY = Severity.Medium
    SHORT_DESCRIPTION = "SAML IdP 'Want AuthnRequests Signed' is disabled"
    LONG_DESCRIPTION = "Keycloak is sending authentication requests to the Identity Provider without a signature. The IdP treats these requests as anonymous, increasing the risk of IdP Confusion attacks and Login CSRF."
    REFERENCE = ""

    def should_consider_idp(self, idp) -> bool:
        pid = getattr(idp, "providerId", "")
        if not pid and isinstance(idp, dict):
            pid = idp.get("providerId", "")
        return pid == "saml"

    @staticmethod
    def _get_config(idp):
        """Helper to safely retrieve the config dictionary."""
        if hasattr(idp, "get_config"):
            return idp.get_config()
        elif hasattr(idp, "config"):
            return idp.config
        elif isinstance(idp, dict):
            return idp.get("config", {})
        else:
            return getattr(idp, "config", {})

    def is_vulnerable(self, idp) -> bool:
        config = self._get_config(idp)
        # Check if wantAuthnRequestsSigned is enabled
        val = config.get("wantAuthnRequestsSigned", "false")
        return val != "true"

    def audit(self):
        # Safe iterator retrieval
        if hasattr(self._DB, "get_all_identity_providers"):
            iterator = self._DB.get_all_identity_providers()
        else:
            iterator = []
            for realm in self._DB.get_all_realms():
                if hasattr(realm, "identity_providers"):
                    iterator.extend(realm.identity_providers)
                elif isinstance(realm, dict):
                    iterator.extend(realm.get("identityProviders", []))

        for idp in iterator:
            if self.should_consider_idp(idp):
                if self.is_vulnerable(idp):
                    yield self.generate_finding(idp)