from kcwarden.api import Auditor
from kcwarden.custom_types.result import Severity


class IdentityProviderWithOneTimeSync(Auditor):
    DEFAULT_SEVERITY = Severity.Info
    SHORT_DESCRIPTION = "Identity Provider does not accept updates from upstream IDP"
    LONG_DESCRIPTION = "Keycloak allows you to configure external identity providers. By default, on the first login, information about the user is pulled from the upstream IDP and imported into Keycloak. Subsequent updates of the user in the upstream IDP (e.g., Name, Email address, ...) are then ignored. If this behavior is intended in your setup, silence this finding. If not, you may want to look into the sync mode 'Force', which will import updates from the upstream IDP on every login (overwriting any changes you may have performed locally)."
    REFERENCE = ""

    def should_consider_idp(self, idp) -> bool:
        return self.is_not_ignored(idp)

    def idp_does_not_use_force_sync_mode(self, idp) -> bool:
        return idp.get_sync_mode() != "FORCE"

    def audit(self):
        for idp in self._DB.get_all_identity_providers():
            # We are looking for IDPs that do not use the "Force" sync mode
            if self.idp_does_not_use_force_sync_mode(idp):
                yield self.generate_finding(idp)
