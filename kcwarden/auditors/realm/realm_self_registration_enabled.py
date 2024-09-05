from kcwarden.api import Auditor
from kcwarden.custom_types.result import Severity


class RealmSelfRegistrationEnabled(Auditor):
    DEFAULT_SEVERITY = Severity.Info
    SHORT_DESCRIPTION = "Self-Registration enabled"
    LONG_DESCRIPTION = "The realm supports self-registration, which means that anyone can register an account. In some cases, this may not be desired, hence kcwarden is flagging this behavior."
    REFERENCE = ""

    def should_consider_realm(self, realm) -> bool:
        return self.is_not_ignored(realm)

    def realm_has_self_registration_enabled(self, realm) -> bool:
        return realm.is_self_registration_enabled()

    def audit(self):
        for realm in self._DB.get_all_realms():
            if self.should_consider_realm(realm):
                if self.realm_has_self_registration_enabled(realm):
                    yield self.generate_finding(realm)
