from kcwarden.api import Auditor
from kcwarden.custom_types.result import Severity

class SamlIdpPostBindingResponseCheck(Auditor):
    DEFAULT_SEVERITY = Severity.Low
    SHORT_DESCRIPTION = "SAML IdP uses HTTP-Redirect (GET) binding"
    LONG_DESCRIPTION = "The 'Post Binding Response' setting is disabled, forcing the use of HTTP-Redirect (GET). This places the entire SAML XML payload into URL query parameters, leading to potential data leakage in logs and Denial of Service due to URL length limits."
    REFERENCE = ""

    def should_consider_idp(self, idp) -> bool:
        return self.is_not_ignored(idp) and idp.get_provider_id() == "saml"

    def is_vulnerable(self, idp) -> bool:
        config = idp.get_config()
        return config.get("postBindingResponse", "false") != "true"

    def audit(self):
        for idp in self._DB.get_all_identity_providers():
            if not self.should_consider_idp(idp):
                continue
            if not self.is_vulnerable(idp):
                continue  
            yield self.generate_finding(idp)