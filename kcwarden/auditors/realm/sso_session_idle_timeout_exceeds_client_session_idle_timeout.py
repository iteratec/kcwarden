from typing import Generator

from kcwarden.auditors.realm.abstract_realm_auditor import AbstractRealmAuditor
from kcwarden.custom_types.keycloak_object import Realm
from kcwarden.custom_types.result import Severity, Result

MAX_SSO_SESSION_IDLE_TIMEOUT_SECONDS = 3600
SSO_SESSION_IDLE_TIMEOUT_HIGH_SECONDS = 28800
SSO_SESSION_IDLE_TIMEOUT_CRITICAL_SECONDS = 86400


class SsoSessionIdleTimeoutExceedsClientSessionIdleTimeout(AbstractRealmAuditor):
    DEFAULT_SEVERITY = Severity.Medium
    SHORT_DESCRIPTION = "SSO session idle timeout exceeds client session idle timeout"
    LONG_DESCRIPTION = (
        "The SSO session idle timeout is set to more than "
        f"{MAX_SSO_SESSION_IDLE_TIMEOUT_SECONDS // 60} minutes, but the client session idle timeout "
        "is either not configured (0) or is not shorter than the SSO session idle timeout, meaning "
        "clients inherit or exceed the long SSO session idle timeout. "
        "Setting a dedicated client session idle timeout that is shorter than the SSO session idle "
        "timeout limits how long individual client sessions remain valid, independently of the SSO session. "
        "Note that the effective idle timeout (client session idle timeout if set, otherwise SSO session idle timeout) "
        "also determines the lifetime of refresh tokens."
    )
    REFERENCE = "https://www.keycloak.org/docs/latest/server_admin/#_timeouts"

    @staticmethod
    def _severity_for_sso_idle(sso_idle: int) -> Severity:
        if sso_idle >= SSO_SESSION_IDLE_TIMEOUT_CRITICAL_SECONDS:
            return Severity.Critical
        if sso_idle >= SSO_SESSION_IDLE_TIMEOUT_HIGH_SECONDS:
            return Severity.High
        return Severity.Medium

    def audit_realm(self, realm: Realm) -> Generator[Result, None, None]:
        sso_idle = realm.get_sso_session_idle_timeout()
        client_idle = realm.get_client_session_idle_timeout()
        if (sso_idle > MAX_SSO_SESSION_IDLE_TIMEOUT_SECONDS and client_idle == 0) or (
            client_idle > 0 and client_idle >= sso_idle
        ):
            yield self.generate_finding(
                realm,
                override_severity=self._severity_for_sso_idle(sso_idle),
                additional_details={
                    "sso_session_idle_timeout": sso_idle,
                    "client_session_idle_timeout": client_idle,
                },
            )
