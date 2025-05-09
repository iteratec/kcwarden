from kcwarden.api.auditor import ClientAuditor
from kcwarden.custom_types.keycloak_object import Client
from kcwarden.custom_types.result import Severity


class ClientShouldNotUseWildcardRedirectURI(ClientAuditor):
    DEFAULT_SEVERITY = Severity.Info
    SHORT_DESCRIPTION = "Clients should not use wildcard redirect URIs"
    LONG_DESCRIPTION = "Authorization responses contain sensitive data, like the OAuth Response Code, which should not be exposed. Therefore, the redirect_uri should not be set with a wildcard, if possible. If a wildcard is required, it should still be as specific as possible."
    REFERENCE = ""

    def should_consider_client(self, client) -> bool:
        # We are interested in clients that are:
        # - OIDC Clients
        # - At least one flow that uses the redirect_uri active
        # TODO Are there more flows that use redirect_uri?
        return (
            super().should_consider_client(client)
            and not client.is_realm_specific_client()
            and client.is_oidc_client()
            and (client.has_standard_flow_enabled() or client.has_implicit_flow_enabled())
        )

    @staticmethod
    def redirect_uri_is_wildcard_uri(redirect) -> bool:
        # The only place Keycloak allows wildcards in a redirect URI is at the very end.
        # So the first approximation can be "is the last character a *?"
        return redirect[-1:] == "*"

    def audit_client(self, client: Client):
        # These clients should use either a localhost or an HTTPS URI
        redirect_uris = client.get_resolved_redirect_uris()
        for redirect in redirect_uris:
            if self.redirect_uri_is_wildcard_uri(redirect):
                yield self.generate_finding(client, additional_details={"redirect_uri": redirect})
