from typing import Generator

from kcwarden.auditors.realm.abstract_realm_auditor import AbstractRealmAuditor
from kcwarden.custom_types.keycloak_object import Realm
from kcwarden.custom_types.result import Severity, Result


class RealmBruteForceProtectionDisabled(AbstractRealmAuditor):
    DEFAULT_SEVERITY = Severity.Info
    SHORT_DESCRIPTION = "Brute-force protection disabled"
    LONG_DESCRIPTION = "The realm does not have brute-force protection enabled, meaning that is vulnerable to password guessing attacks."
    REFERENCE = ""

    @staticmethod
    def realm_has_brute_force_protection_disabled(realm: Realm) -> bool:
        return not realm.is_brute_force_protected()

    def audit_realm(self, realm: Realm) -> Generator[Result, None, None]:
        if self.realm_has_brute_force_protection_disabled(realm):
            yield self.generate_finding(realm)
