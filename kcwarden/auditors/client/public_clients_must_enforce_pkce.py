from kcwarden.api import Auditor
from kcwarden.custom_types.result import Severity


class PublicClientsMustEnforcePKCE(Auditor):
    DEFAULT_SEVERITY = Severity.High
    SHORT_DESCRIPTION = "Public Clients MUST use and enforce PKCE"
    LONG_DESCRIPTION = "Public Clients using the Authorization Code Grant flow (called 'standard flow' in Keycloak) MUST use PKCE when using the Authorization Code Flow. Otherwise, they may be vulnerable to authorization code injection, Cross-Site Request Forgery (CSRF), or other attacks. PKCE must also be enforced in the Keycloak client settings by setting the PKCE Code Challenge Method to 'S256'. Other methods are less secure."
    REFERENCE = "https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics-23#section-2.1.1"

    def should_consider_client(self, client) -> bool:
        # We are interested in clients that are:
        # - OIDC Clients
        # - Public
        # - Have the standard flow enabled
        return (
            self.is_not_ignored(client)
            and not client.is_realm_specific_client()
            and client.is_oidc_client()
            and client.is_public()
            and client.has_standard_flow_enabled()
        )

    def client_does_not_enforce_pkce(self, client) -> bool:
        # Clients should use PKCE and pin to S256 as the algorithm
        return client.get_attributes().get("pkce.code.challenge.method", None) != "S256"

    def audit(self):
        for client in self._DB.get_all_clients():
            if self.should_consider_client(client):
                if self.client_does_not_enforce_pkce(client):
                    yield self.generate_finding(client)
