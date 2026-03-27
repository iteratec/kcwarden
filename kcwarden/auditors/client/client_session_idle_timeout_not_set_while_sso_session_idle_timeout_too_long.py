from kcwarden.api.auditor import ClientAuditor
from kcwarden.auditors.realm.sso_session_idle_timeout_exceeds_client_session_idle_timeout import (
    MAX_SSO_SESSION_IDLE_TIMEOUT_SECONDS,
)
from kcwarden.custom_types.keycloak_object import Client
from kcwarden.custom_types.result import Severity


class ClientSessionIdleTimeoutNotSetWhileSsoSessionIdleTimeoutTooLong(ClientAuditor):
    DEFAULT_SEVERITY = Severity.Medium
    SHORT_DESCRIPTION = "Client inherits long SSO session idle timeout without a client-specific override"
    LONG_DESCRIPTION = (
        f"The realm SSO session idle timeout exceeds {MAX_SSO_SESSION_IDLE_TIMEOUT_SECONDS // 60} minutes "
        "and no realm-level client session idle timeout is configured, meaning all clients inherit the long "
        "SSO session idle timeout by default. "
        "This client does not define its own session idle timeout override, so its sessions — and the "
        "associated refresh tokens — remain valid for the full SSO session idle timeout duration. "
        "Consider setting a dedicated client session idle timeout on this client to limit session and "
        "refresh token validity independently of the SSO session."
    )
    REFERENCE = "https://www.keycloak.org/docs/latest/server_admin/#_timeouts"

    def should_consider_client(self, client: Client) -> bool:
        return super().should_consider_client(client) and client.is_oidc_client()

    def audit_client(self, client: Client):
        realm = client.get_realm()
        sso_idle = realm.get_sso_session_idle_timeout()
        client_override = client.get_client_session_idle_timeout_override()
        if (
            sso_idle > MAX_SSO_SESSION_IDLE_TIMEOUT_SECONDS
            and realm.get_client_session_idle_timeout() == 0
            and client_override == 0
        ) or (client_override > 0 and client_override >= sso_idle):
            yield self.generate_finding(
                client,
                additional_details={
                    "realm_sso_session_idle_timeout": sso_idle,
                    "realm_client_session_idle_timeout": realm.get_client_session_idle_timeout(),
                    "client_session_idle_timeout_override": client_override,
                },
            )
