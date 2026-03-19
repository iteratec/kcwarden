from kcwarden.api.auditor import ClientAuditor
from kcwarden.custom_types.keycloak_object import Client
from kcwarden.custom_types.result import Severity


class ClientWebOriginsMustNotUseWildcard(ClientAuditor):
    DEFAULT_SEVERITY = Severity.Medium
    SHORT_DESCRIPTION = "Client allows all origins for CORS requests via wildcard"
    LONG_DESCRIPTION = (
        "The webOrigins setting controls which origins are permitted to make CORS requests to this client. "
        "Setting it to '*' allows any origin to send cross-origin requests, bypassing the browser's same-origin policy. "
        "This can expose the client's endpoints to cross-site request forgery and data exfiltration from malicious websites. "
        "Instead, explicitly list only the origins that are legitimately allowed to interact with this client."
    )
    REFERENCE = "https://datatracker.ietf.org/doc/html/rfc6454#section-3.2"

    def should_consider_client(self, client: Client) -> bool:
        return super().should_consider_client(client) and client.is_oidc_client()

    def audit_client(self, client: Client):
        if "*" in client.get_web_origins():
            yield self.generate_finding(client)
