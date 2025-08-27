from kcwarden.api.auditor import ClientAuditor
from kcwarden.auditors.subchecks.access_tokens import (
    MAX_ACCESS_TOKEN_LIFESPAN_SECONDS,
    access_token_lifespan_is_too_long,
)
from kcwarden.custom_types.keycloak_object import Client
from kcwarden.custom_types.result import Severity


class ClientAccessTokenLifespanTooLong(ClientAuditor):
    DEFAULT_SEVERITY = Severity.High
    SHORT_DESCRIPTION = "Access token lifespan override too long"
    LONG_DESCRIPTION = (
        "Client-specific token lifespan overrides should be short "
        "to minimize the potential impact of token compromise. "
        "Consider removing the client-specific override or reducing it to "
        f"{MAX_ACCESS_TOKEN_LIFESPAN_SECONDS / 60:.0f} minutes or less."
    )
    REFERENCE = ""

    def should_consider_client(self, client: Client) -> bool:
        return super().should_consider_client(client) and client.is_oidc_client()

    @staticmethod
    def client_has_access_token_lifespan_override_too_long(client: Client) -> bool:
        override_lifespan = client.get_access_token_lifespan_override()
        if override_lifespan is None:
            return False
        return access_token_lifespan_is_too_long(override_lifespan)

    def audit_client(self, client: Client):
        if self.client_has_access_token_lifespan_override_too_long(client):
            override_lifespan = client.get_access_token_lifespan_override()
            yield self.generate_finding(
                client,
                additional_details={
                    "client_access_token_lifespan": override_lifespan,
                    "realm_access_token_lifespan": client.get_realm().get_access_token_lifespan(),
                },
            )
