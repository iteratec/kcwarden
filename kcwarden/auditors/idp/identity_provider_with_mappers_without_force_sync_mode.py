from kcwarden.api import Auditor
from kcwarden.custom_types.result import Severity


class IdentityProviderWithMappersWithoutForceSyncMode(Auditor):
    DEFAULT_SEVERITY = Severity.Medium
    SHORT_DESCRIPTION = "Identity Provider uses upstream data, but does not update it"
    LONG_DESCRIPTION = "Keycloak allows you to configure external identity providers. You can also set up one or more Identity Provider Mappers, which pull information from the access token of the IDP and import it into Keycloak. By default, this import only happens on the first login, and any future updates in the upstream IDP are ignored. If you use mappers to assign groups or other access rights, this means that the rights will not be updated if the upstream IDP changes them. This may be intended by you (in which case you can silence this finding), but it may also be a security bug. To accept updates from upstream, you can set the sync mode to 'Force', either for the entire IDP (in which case it will also overwrite user information like name and email on each login), or for the relevant mappers. This finding has a higher severity than the IdentityProviderWithOneTimeSync finding, as the configured IDP uses at least one Identity Provider Mapper."
    REFERENCE = ""

    def should_consider_idp(self, idp) -> bool:
        return self.is_not_ignored(idp)

    @staticmethod
    def idp_uses_sync_mode_force(idp) -> bool:
        return idp.get_sync_mode() == "FORCE"

    @staticmethod
    def idp_uses_information_from_access_token(idp) -> bool:
        return idp.get_identity_provider_mappers() != []

    def audit(self):
        for idp in self._DB.get_all_identity_providers():
            # Skip IDPs that were explicitly ignored
            if not self.should_consider_idp(idp):
                continue
            # We are looking for IDPs that do not use the "Force" sync mode
            if self.idp_uses_sync_mode_force(idp):
                continue
            # Among these, we are looking for ones that are pulling information from the token
            if self.idp_uses_information_from_access_token(idp):
                yield self.generate_finding(idp)
