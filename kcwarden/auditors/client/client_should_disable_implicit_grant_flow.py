from kcwarden.api.auditor import ClientAuditor
from kcwarden.custom_types.keycloak_object import Client
from kcwarden.custom_types.result import Severity


class ClientShouldDisableImplicitGrantFlow(ClientAuditor):
    DEFAULT_SEVERITY = Severity.Medium
    SHORT_DESCRIPTION = "The 'implicit grant' flow SHOULD NOT be used"
    LONG_DESCRIPTION = "The implicit grant flow exposes the access token in the URL, which can lead to access token leakage or replay vulnerabilities. The 'Authorization Code' flow (called 'Standard Flow' in Keycloak) should be used, and the implicit flow disabled in Keycloak."
    REFERENCE = "https://datatracker.ietf.org/doc/html/rfc9700#section-2.1.2"

    def should_consider_client(self, client) -> bool:
        # We are interested in clients that are:
        # - OIDC Clients
        return (
            super().should_consider_client(client) and client.is_oidc_client() and not client.is_realm_specific_client()
        )

    @staticmethod
    def client_uses_implicit_grant_flow(client) -> bool:
        # All clients that have implicit flow enabled are considered suspect
        return client.has_implicit_flow_enabled()

    def audit_client(self, client: Client):
        if self.client_uses_implicit_grant_flow(client):
            yield self.generate_finding(client)
