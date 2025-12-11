from typing import Generator

from kcwarden.auditors.realm.abstract_realm_auditor import AbstractRealmAuditor
from kcwarden.custom_types.keycloak_object import Realm
from kcwarden.custom_types.result import Severity, Result


class PasswordPolicyMissing(AbstractRealmAuditor):
    DEFAULT_SEVERITY = Severity.High
    SHORT_DESCRIPTION = "Password policy is missing"
    LONG_DESCRIPTION = (
        "No password policy has been defined. By default Keycloak does not enforce any password policy. "
        "This may lead to insecure passwords being used by users. "
        "Consider defining a password policy that enforces strong passwords."
    )
    REFERENCE = "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html#implement-proper-password-strength-controls"

    @staticmethod
    def realm_has_no_password_policy(realm: Realm) -> bool:
        policy_str: str = realm._d.get("passwordPolicy", "")
        return len(policy_str) == 0

    def audit_realm(self, realm: Realm) -> Generator[Result, None, None]:
        if self.realm_has_no_password_policy(realm):
            yield self.generate_finding(realm)
