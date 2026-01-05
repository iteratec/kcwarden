from kcwarden.api import Auditor
from kcwarden.custom_types.result import Severity

class IdpPostBindingResponseCheck(Auditor):
    DEFAULT_SEVERITY = Severity.Low
    SHORT_DESCRIPTION = "SAML IdP uses HTTP-Redirect (GET) binding"
    LONG_DESCRIPTION = "The 'Post Binding Response' setting is disabled, forcing the use of HTTP-Redirect (GET). This places the entire SAML XML payload into URL query parameters, leading to potential data leakage in logs and Denial of Service due to URL length limits."
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
        # If "postBindingResponse" is false, it uses Redirect (GET), which is the risk.
        val = config.get("postBindingResponse", "false")
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