from kcwarden.api import Auditor
from kcwarden.custom_types.result import Severity


class ConfidentialClientShouldDisableDirectAccessGrants(Auditor):
    DEFAULT_SEVERITY = Severity.Medium
    SHORT_DESCRIPTION = "The 'direct access grant' flow MUST NOT be used"
    LONG_DESCRIPTION = "The resource owner password credentials grant (called 'direct access grant' in Keycloak) requires the client to submit username and password of the authenticating user. This greatly increases the attack surface for the credentials, as they are exposed outside of Keycloak. Additionally, it is generally incompatible with two-factor-authentication methods like WebAuthN or SMS tokens. This flow MUST NOT be used, and should be disabled on all clients. While it is less dangerous in the case of confidential clients like this one, as using the client requires knowledge of the client secret, the same recommendation still applies. (Some systems use the direct access grant flow to obtain tokens for technical users. In this case, please note that using technical users is strongly discouraged in favor of the 'service accounts' feature of Keycloak.)"
    REFERENCE = "https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics-23#section-2.4"

    def should_consider_client(self, client) -> bool:
        # We are interested in clients that are:
        # - OIDC clients
        # - Are confidential clients
        return (self.is_not_ignored(client) 
                and not client.is_realm_specific_client()
                and client.is_oidc_client() 
                and not client.is_public()
        )

    def client_uses_direct_access_grants(self, client) -> bool:
        # All clients with direct access grants should be reported
        return client.has_direct_access_grants_enabled()

    def audit(self):
        for client in self._DB.get_all_clients():
            if self.should_consider_client(client):
                if self.client_uses_direct_access_grants(client):
                    yield self.generate_finding(client)
