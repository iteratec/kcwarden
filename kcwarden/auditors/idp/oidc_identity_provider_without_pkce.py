from kcwarden.api import Auditor
from kcwarden.custom_types.result import Severity


class OIDCIdentityProviderWithoutPKCE(Auditor):
    DEFAULT_SEVERITY = Severity.Medium
    SHORT_DESCRIPTION = "OIDC Identity Provider configured without PKCE"
    LONG_DESCRIPTION = "The realm has configured an OIDC Identity Provider, but does not enable PKCE for it. PKCE prevents different kinds of attacks on the OIDC protocol, and it is RECOMMENDED to enable it."
    REFERENCE = "https://datatracker.ietf.org/doc/html/rfc9700#section-2.1.1"

    def should_consider_idp(self, idp) -> bool:
        # We are interested in identity providers that are:
        # - using either the "oidc" or the "keycloak-oidc" provider (the others don't allow configuring the setting)
        return idp.get_provider_id() in ["oidc", "keycloak-oidc"] and self.is_not_ignored(idp)

    @staticmethod
    def idp_does_not_enforce_pkce(cfg) -> bool:
        # TODO Refactor with .get once unit tests exist
        # Flag IDPs that:
        # - Either do not explicitly state the PKCE status, or have it set to false
        # - Alternatively, they use PKCE, but use it in 'plain' mode (the default, for some reason)
        return "pkceEnabled" not in cfg or cfg["pkceEnabled"] != "true" or cfg["pkceMethod"] != "S256"

    def audit(self):
        for idp in self._DB.get_all_identity_providers():
            # - Either do not explicitly state the PKCE status, or have it set to false
            # - Alternatively, they use PKCE, but use it in 'plain' mode (the default, for some reason)
            if not self.should_consider_idp(idp):
                continue
            cfg = idp.get_config()
            if self.idp_does_not_enforce_pkce(cfg):
                yield self.generate_finding(
                    idp,
                    additional_details={
                        "pkceEnabled": cfg.get("pkceEnabled", "[unset, defaults to false]"),
                        "pkceMethod": cfg.get("pkceMethod", "[unset]"),
                    },
                )
