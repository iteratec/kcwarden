from typing import Generator

from kcwarden.auditors.realm.abstract_realm_auditor import AbstractRealmAuditor
from kcwarden.custom_types.keycloak_object import Realm
from kcwarden.custom_types.result import Severity, Result


class RealmEmailVerificationDisabled(AbstractRealmAuditor):
    DEFAULT_SEVERITY = Severity.Info
    SHORT_DESCRIPTION = "Email verification disabled"
    LONG_DESCRIPTION = "The realm does not have email verification enabled, meaning that email addresses of users haven't been verified using a double opt-in mechanism. Depending on the source of the addresses, they may not be trustworthy."
    REFERENCE = ""

    @staticmethod
    def realm_has_email_verification_disabled(realm) -> bool:
        return not realm.is_verify_email_enabled()

    def audit_realm(self, realm: Realm) -> Generator[Result, None, None]:
        if self.realm_has_email_verification_disabled(realm):
            yield self.generate_finding(realm)
