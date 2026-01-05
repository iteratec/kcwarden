from kcwarden.api import Auditor
from kcwarden.custom_types.result import Severity

class IdpWantAssertionsEncryptedCheck(Auditor):
    DEFAULT_SEVERITY = Severity.Medium
    SHORT_DESCRIPTION = "SAML IdP 'Want Assertions Encrypted' is disabled"
    LONG_DESCRIPTION = "The Identity Provider accepts unencrypted assertions. This exposes PII to intermediaries and makes the system more susceptible to XML Signature Wrapping (XSW) attacks."
    REFERENCE = ""

    def should_consider_idp(self, idp) -> bool:
        pid = getattr(idp, "providerId", "")
        if not pid and isinstance(idp, dict):
            pid = idp.get("providerId", "")
        return pid == "saml"

    def is_vulnerable(self, idp) -> bool:
        config = idp.get_config()
        # Check specific key for encryption
        val = config.get("wantAssertionsEncrypted", "false")
        return val != "true"

    def audit(self):
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