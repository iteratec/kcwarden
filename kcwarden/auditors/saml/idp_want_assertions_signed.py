from kcwarden.api import Auditor
from kcwarden.custom_types.result import Severity

class IdpWantAssertionsSignedCheck(Auditor):
    DEFAULT_SEVERITY = Severity.High
    SHORT_DESCRIPTION = "SAML IdP 'Want Assertions Signed' is disabled"
    LONG_DESCRIPTION = "The Identity Provider does not require SAML Assertions to be signed. This may allow attackers to modify the assertion content (e.g., username/roles) even if the envelope signature is valid, or if used in conjunction with other flaws."
    REFERENCE = ""

    def should_consider_idp(self, idp) -> bool:
        pid = getattr(idp, "providerId", "")
        if not pid and isinstance(idp, dict):
            pid = idp.get("providerId", "")
        return pid == "saml"

    @staticmethod
    def _get_config(idp):
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
        # Check specific key for assertions signed
        val = config.get("wantAssertionsSigned", "false")
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