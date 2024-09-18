from kcwarden.api import Auditor
from kcwarden.custom_types.result import Severity


class ClientShouldDisableImplicitGrantFlow(Auditor):
    DEFAULT_SEVERITY = Severity.Medium
    SHORT_DESCRIPTION = "The 'implicit grant' flow SHOULD NOT be used"
    LONG_DESCRIPTION = "The implicit grant flow exposes the access token in the URL, which can lead to access token leakage or replay vulnerabilities. The 'Authorization Code' flow (called 'Standard Flow' in Keycloak) should be used, and the implicit flow disabled in Keycloak."
    REFERENCE = "https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics-23#section-2.1.2"

    def should_consider_client(self, client) -> bool:
        # We are interested in clients that are:
        # - OIDC Clients
        return self.is_not_ignored(client) and client.is_oidc_client() and not client.is_realm_specific_client()

    def client_uses_implicit_grant_flow(self, client) -> bool:
        # All clients that have implicit flow enabled are considered suspect
        return client.has_implicit_flow_enabled()

    def audit(self):
        for client in self._DB.get_all_clients():
            if self.should_consider_client(client):
                if self.client_uses_implicit_grant_flow(client):
                    yield self.generate_finding(client)
