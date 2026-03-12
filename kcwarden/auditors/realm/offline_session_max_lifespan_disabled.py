from typing import Generator

from kcwarden.auditors.realm.abstract_realm_auditor import AbstractRealmAuditor
from kcwarden.custom_types.keycloak_object import Realm
from kcwarden.custom_types.result import Severity, Result


class OfflineSessionMaxLifespanDisabled(AbstractRealmAuditor):
    DEFAULT_SEVERITY = Severity.Info
    SHORT_DESCRIPTION = "Offline session max lifespan disabled"
    LONG_DESCRIPTION = (
        "The realm does not enforce a maximum lifespan for offline sessions. "
        "This means offline tokens can be renewed indefinitely as long as they are used within the idle timeout, "
        "effectively granting permanent access. In environments with upstream identity providers or strict "
        "session governance requirements, this undermines token revocation and session expiry controls."
    )
    REFERENCE = ""

    @staticmethod
    def realm_has_offline_session_max_lifespan_disabled(realm: Realm) -> bool:
        return not realm.is_offline_session_max_lifespan_enabled()

    def audit_realm(self, realm: Realm) -> Generator[Result, None, None]:
        if self.realm_has_offline_session_max_lifespan_disabled(realm):
            yield self.generate_finding(
                realm,
                additional_details={
                    "offline_session_idle_timeout": realm.get_offline_session_idle_timeout(),
                },
            )
