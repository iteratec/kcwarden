from kcwarden.api import Auditor
from kcwarden.custom_types.result import Severity


class OIDCIdentityProviderWithSignatureVerificationDisabled(Auditor):
    DEFAULT_SEVERITY = Severity.Critical
    SHORT_DESCRIPTION = "OIDC Identity Provider does not verify upstream IDPs signatures"
    LONG_DESCRIPTION = "Keycloak allows you to configure external identity providers. When using OpenID Connect, it is important to verify the cryptographic signature that secures the identity and access tokens generated by the identity provider. This IDP configuration disables this signature check, which makes it vulnerable to accepting forged access tokens, leading to account takeover and other security issues."
    REFERENCE = ""

    def should_consider_idp(self, idp) -> bool:
        return self.is_not_ignored(idp) and idp.get_provider_id() in ["oidc", "keycloak-oidc"]

    def idp_does_not_verify_signatures(self, config):
        return config.get("validateSignature") == "false"

    def audit(self):
        for idp in self._DB.get_all_identity_providers():
            # Skip IDPs that were explicitly ignored, or that aren't OIDC IDPs
            if not self.should_consider_idp(idp):
                continue
            # Check if signature verification is disabled
            if self.idp_does_not_verify_signatures(idp.get_config()):
                yield self.generate_finding(idp)
