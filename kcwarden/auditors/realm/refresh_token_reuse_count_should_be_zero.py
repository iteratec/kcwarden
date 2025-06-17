from typing import Generator

from kcwarden.auditors.realm.abstract_realm_auditor import AbstractRealmAuditor
from kcwarden.custom_types.keycloak_object import Realm
from kcwarden.custom_types.result import Severity, Result


class RefreshTokenReuseCountShouldBeZero(AbstractRealmAuditor):
    DEFAULT_SEVERITY = Severity.Medium
    SHORT_DESCRIPTION = "Refresh tokens MUST be invalidated after use"
    LONG_DESCRIPTION = "Refresh tokens allow a client to obtain a new access token. However, if they get leaked, it may allow an attacker to obtain a long-lived session. Thus, they MUST be rotated after use. In this case, the realm is configured to revoke refresh tokens after a set number of uses, but allows the token to be used more than once. This weakens the security of the setting. (Be advised that at the time of writing, revoking refresh tokens may have undesired results when more than one refresh token can be issued by the same client to the same user, for example in some methods of keeping keys in the frontend. Please consult the following Keycloak issue for more details: https://github.com/keycloak/keycloak/issues/14122)"
    REFERENCE = "https://datatracker.ietf.org/doc/html/rfc9700#section-2.2.2"

    @staticmethod
    def realm_has_refresh_token_reuse_enabled(realm) -> bool:
        return realm.has_refresh_token_revocation_enabled() and realm.get_refresh_token_maximum_reuse_count() > 0

    def audit_realm(self, realm: Realm) -> Generator[Result, None, None]:
        # Find realms that have refresh token revocation enabled, but allow a token to be reused more than once
        if self.realm_has_refresh_token_reuse_enabled(realm):
            yield self.generate_finding(realm)
