from kcwarden.api import Auditor
from kcwarden.custom_types.result import Severity


class RealmEmailVerificationDisabled(Auditor):
    DEFAULT_SEVERITY = Severity.Info
    SHORT_DESCRIPTION = "Email verification disabled"
    LONG_DESCRIPTION = "The realm does not have email verification enabled, meaning that email addresses of users haven't been verified using a double opt-in mechanism. Depending on the source of the addresses, they may not be trustworthy."
    REFERENCE = ""

    def should_consider_realm(self, realm) -> bool:
        return self.is_not_ignored(realm)

    def realm_has_email_verification_disabled(self, realm) -> bool:
        return not realm.is_verify_email_enabled()

    def audit(self):
        for realm in self._DB.get_all_realms():
            if self.should_consider_realm(realm):
                if self.realm_has_email_verification_disabled(realm):
                    yield self.generate_finding(realm)
