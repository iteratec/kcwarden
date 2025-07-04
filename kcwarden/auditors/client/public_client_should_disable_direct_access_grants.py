from kcwarden.api.auditor import ClientAuditor
from kcwarden.custom_types.keycloak_object import Client
from kcwarden.custom_types.result import Severity


class PublicClientShouldDisableDirectAccessGrants(ClientAuditor):
    DEFAULT_SEVERITY = Severity.High
    SHORT_DESCRIPTION = "The 'direct access grant' flow MUST NOT be used, particularly not by public clients"
    LONG_DESCRIPTION = "The resource owner password credentials grant (called 'direct access grant' in Keycloak) requires the client to submit username and password of the authenticating user. This greatly increases the attack surface for the credentials, as they are exposed outside of Keycloak. Additionally, it is generally incompatible with two-factor-authentication methods like WebAuthN or SMS tokens. This flow MUST NOT be used, and should be disabled on all clients. This is especially important on public clients like this one, as they allow anyone to authenticate using Direct Access Grants, not just the rightful user of the client, as in the case of confidential clients. (Some systems use the direct access grant flow to obtain tokens for technical users. In this case, please note that using technical users is strongly discouraged in favor of the 'service accounts' feature of Keycloak.)"
    REFERENCE = "https://datatracker.ietf.org/doc/html/rfc9700#section-2.4"

    def should_consider_client(self, client) -> bool:
        # We are interested in clients that are:
        # - OIDC clients
        # - Are public clients
        return (
            super().should_consider_client(client)
            and not client.is_realm_specific_client()
            and client.is_oidc_client()
            and client.is_public()
        )

    @staticmethod
    def client_uses_direct_access_grants(client) -> bool:
        # All clients with direct access grants should be reported
        return client.has_direct_access_grants_enabled()

    def audit_client(self, client: Client):
        if self.client_uses_direct_access_grants(client):
            yield self.generate_finding(client)
