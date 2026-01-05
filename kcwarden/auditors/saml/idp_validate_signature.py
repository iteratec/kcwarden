from kcwarden.api import Auditor
from kcwarden.custom_types.result import Severity

class IdpValidateSignatureCheck(Auditor):
    DEFAULT_SEVERITY = Severity.High
    SHORT_DESCRIPTION = "SAML IdP 'Validate Signature' is disabled"
    LONG_DESCRIPTION = "The Identity Provider is configured with 'validateSignature' set to false. Keycloak will not verify the digital signature of incoming SAML documents, allowing for token forgery."
    REFERENCE = ""

    def should_consider_idp(self, idp) -> bool:
        # Check if this is a SAML provider
        pid = getattr(idp, "providerId", "")
        # Handle cases where providerId might be accessed differently
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
        val = config.get("validateSignature", "false")
        return val != "true"

    def audit(self):
        # If get_all_identity_providers() does not exist, check get_all_realms() -> idps
        if hasattr(self._DB, "get_all_identity_providers"):
            iterator = self._DB.get_all_identity_providers()
        else:
            # Fallback for some versions: iterate realms
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