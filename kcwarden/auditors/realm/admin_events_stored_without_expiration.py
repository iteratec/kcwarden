from typing import Generator

from kcwarden.auditors.realm.abstract_realm_auditor import AbstractRealmAuditor
from kcwarden.custom_types.keycloak_object import Realm
from kcwarden.custom_types.result import Severity, Result


class AdminEventsStoredWithoutExpiration(AbstractRealmAuditor):
    DEFAULT_SEVERITY = Severity.Low
    SHORT_DESCRIPTION = "Admin events are stored without expiration"
    LONG_DESCRIPTION = (
        "The realm stores admin events, but no expiration is configured. Keycloak then keeps these events forever, "
        "which lets the admin event table grow indefinitely. This costs disk space, can degrade the performance of "
        "event queries, and slows down database dumps and restores. Additionally, admin events contain PII "
        "(such as IP addresses, user IDs and, if representations are included, user details) which is retained "
        "indefinitely and may violate data protection regulations like the GDPR. "
        "Configure an expiration for admin events. "
        "If events need to be retained permanently, e.g. for auditing or compliance reasons, they should be "
        "forwarded to and stored in an external third-party system (such as a SIEM or log management system) "
        "instead of the Keycloak database."
    )
    REFERENCE = "https://www.keycloak.org/docs/latest/server_admin/#configuring-auditing-to-track-events"

    @staticmethod
    def realm_stores_admin_events_without_expiration(realm: Realm) -> bool:
        return realm.is_admin_events_enabled() and realm.get_admin_events_expiration() <= 0

    def audit_realm(self, realm: Realm) -> Generator[Result, None, None]:
        if self.realm_stores_admin_events_without_expiration(realm):
            yield self.generate_finding(realm)
