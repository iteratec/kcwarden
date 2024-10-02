from typing import Generator

from kcwarden.auditors.realm.abstract_realm_auditor import AbstractRealmAuditor
from kcwarden.custom_types.keycloak_object import Realm
from kcwarden.custom_types.result import Severity, Result


class RealmSelfRegistrationEnabled(AbstractRealmAuditor):
    DEFAULT_SEVERITY = Severity.Info
    SHORT_DESCRIPTION = "Self-Registration enabled"
    LONG_DESCRIPTION = "The realm supports self-registration, which means that anyone can register an account. In some cases, this may not be desired, hence kcwarden is flagging this behavior."
    REFERENCE = ""

    @staticmethod
    def realm_has_self_registration_enabled(realm) -> bool:
        return realm.is_self_registration_enabled()

    def audit_realm(self, realm: Realm) -> Generator[Result, None, None]:
        if self.realm_has_self_registration_enabled(realm):
            yield self.generate_finding(realm)
