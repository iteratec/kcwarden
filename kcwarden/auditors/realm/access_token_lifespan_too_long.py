from typing import Generator

from kcwarden.auditors.realm.abstract_realm_auditor import AbstractRealmAuditor
from kcwarden.auditors.subchecks.access_tokens import (
    access_token_lifespan_is_too_long,
    MAX_ACCESS_TOKEN_LIFESPAN_SECONDS,
)
from kcwarden.custom_types.keycloak_object import Realm
from kcwarden.custom_types.result import Severity, Result


class AccessTokenLifespanTooLong(AbstractRealmAuditor):
    DEFAULT_SEVERITY = Severity.High
    SHORT_DESCRIPTION = "Access token lifespan too long"
    LONG_DESCRIPTION = (
        "Access tokens should have a short lifespan to minimize the impact of potential token "
        "compromise. The lifespan should be set to "
        f"{MAX_ACCESS_TOKEN_LIFESPAN_SECONDS / 60:.0f} minutes or less."
    )
    REFERENCE = ""

    @staticmethod
    def realm_has_access_token_lifespan_too_long(realm: Realm) -> bool:
        """Check if realm's access token lifespan exceeds the maximum allowed duration."""
        return access_token_lifespan_is_too_long(realm.get_access_token_lifespan())

    def audit_realm(self, realm: Realm) -> Generator[Result, None, None]:
        if self.realm_has_access_token_lifespan_too_long(realm):
            yield self.generate_finding(
                realm,
                additional_details={
                    "realm_access_token_lifespan": realm.get_access_token_lifespan(),
                },
            )
