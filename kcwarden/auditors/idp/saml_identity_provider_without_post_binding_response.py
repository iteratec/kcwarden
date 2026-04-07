from kcwarden.api import Auditor
from kcwarden.custom_types.result import Severity


class SamlIdentityProviderWithoutPostBindingResponse(Auditor):
    DEFAULT_SEVERITY = Severity.Medium
    SHORT_DESCRIPTION = "SAML IdP uses HTTP-Redirect (GET) binding"
    LONG_DESCRIPTION = "The 'Post Binding Response' setting is disabled, forcing the use of HTTP-Redirect (GET) binding. With HTTP-Redirect, the entire SAML XML response is Base64-encoded and placed into a URL query parameter. This causes three distinct problems: (1) Credential leakage: URLs are routinely recorded in browser history, server access logs, proxy logs, and Referer headers, exposing the encoded assertion to unintended parties. (2) Denial of Service: the XML payload for assertions with many attributes or roles can easily exceed browser and server URL length limits (typically 2-8 KB), causing intermittent login failures for users with complex role sets. (3) Reduced tamper-resistance: HTTP-POST delivers the payload in the request body, which is not recorded in most logs and has no practical size limit, making it both safer and more robust. We recommend enabling 'Post Binding Response'."
    REFERENCE = ""

    def should_consider_idp(self, idp) -> bool:
        return self.is_not_ignored(idp) and idp.is_saml_provider()

    def audit(self):
        for idp in self._DB.get_all_identity_providers():
            if not self.should_consider_idp(idp):
                continue
            if not idp.is_post_binding_response_enabled():
                yield self.generate_finding(idp)
