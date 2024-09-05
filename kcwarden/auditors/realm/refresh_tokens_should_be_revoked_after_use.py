from kcwarden.api import Auditor
from kcwarden.custom_types.result import Severity


class RefreshTokensShouldBeRevokedAfterUse(Auditor):
    DEFAULT_SEVERITY = Severity.Medium
    SHORT_DESCRIPTION = "Refresh tokens MUST be invalidated after use"
    LONG_DESCRIPTION = "Refresh tokens allow a client to obtain a new access token. However, if they get leaked, it may allow an attacker to obtain a long-lived session. Thus, they MUST be rotated after use. (Be advised that at the time of writing, revoking refresh tokens may have undesired results when more than one refresh token can be issued by the same client to the same user, for example in some methods of keeping keys in the frontend. Please consult the following Keycloak issue for more details: https://github.com/keycloak/keycloak/issues/14122)"
    REFERENCE = "https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics-23#section-2.2.2"

    def should_consider_realm(self, realm) -> bool:
        return self.is_not_ignored(realm)

    def realm_has_refresh_token_revocation_disabled(self, realm) -> bool:
        return not realm.has_refresh_token_revocation_enabled()

    def audit(self):
        for realm in self._DB.get_all_realms():
            # Find realms that have refresh token revocation disabled
            if self.should_consider_realm(realm):
                if self.realm_has_refresh_token_revocation_disabled(realm):
                    yield self.generate_finding(realm)
