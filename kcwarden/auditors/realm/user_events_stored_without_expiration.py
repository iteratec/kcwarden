from typing import Generator

from kcwarden.auditors.realm.abstract_realm_auditor import AbstractRealmAuditor
from kcwarden.custom_types.keycloak_object import Realm
from kcwarden.custom_types.result import Severity, Result


class UserEventsStoredWithoutExpiration(AbstractRealmAuditor):
    DEFAULT_SEVERITY = Severity.Low
    SHORT_DESCRIPTION = "User events are stored without expiration"
    LONG_DESCRIPTION = (
        "The realm stores user events, but no expiration is configured. Keycloak then keeps these events forever, "
        "which lets the event table grow indefinitely. This costs disk space, can degrade the performance of event "
        "queries, and slows down database dumps and restores. Additionally, user events contain PII "
        "(such as IP addresses, user IDs, usernames or email addresses) which is retained indefinitely and may "
        "violate data protection regulations like the GDPR. Configure an expiration for user events. "
        "If events need to be retained permanently, e.g. for auditing or compliance reasons, they should be "
        "forwarded to and stored in an external third-party system (such as a SIEM or log management system) "
        "instead of the Keycloak database."
    )
    REFERENCE = "https://www.keycloak.org/docs/latest/server_admin/#configuring-auditing-to-track-events"

    @staticmethod
    def realm_stores_user_events_without_expiration(realm: Realm) -> bool:
        return realm.is_user_events_enabled() and realm.get_user_events_expiration() <= 0

    def audit_realm(self, realm: Realm) -> Generator[Result, None, None]:
        if self.realm_stores_user_events_without_expiration(realm):
            yield self.generate_finding(realm)
