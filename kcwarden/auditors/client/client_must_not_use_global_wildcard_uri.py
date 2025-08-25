from urllib.parse import urlparse

from kcwarden.api.auditor import ClientAuditor
from kcwarden.custom_types.keycloak_object import Client
from kcwarden.custom_types.result import Severity


class ClientMustNotUseGlobalWildcardURI(ClientAuditor):
    DEFAULT_SEVERITY = Severity.Critical
    SHORT_DESCRIPTION = "Erroneously configured redirect URI allows any URIs for redirects"
    LONG_DESCRIPTION = "Authorization responses contain sensitive data, like the OAuth Response Code, which should not be exposed. Keycloak requires specifying an allowed set of redirect URIs. In this case, a redirect URI was set to a global wildcard (*). This allows arbitrary URIs to be specified as a redirect URI without any requirements. This should be set to a specific path or at least to a specific as possible wildcard URI."
    REFERENCE = ""

    def should_consider_client(self, client) -> bool:
        # We are interested in clients that are:
        # - OIDC Clients
        # - At least one flow that uses the redirect_uri active
        return (
            super().should_consider_client(client)
            and not client.is_realm_specific_client()
            and client.is_oidc_client()
            and (client.has_standard_flow_enabled() or client.has_implicit_flow_enabled())
        )

    @staticmethod
    def redirect_uri_is_global_wildcard(redirect: str) -> bool:
        if redirect == "*":
            return True
        parsed_redirect = urlparse(redirect)
        return parsed_redirect.netloc == "*"

    def audit_client(self, client: Client):
        redirect_uris = client.get_resolved_redirect_uris()
        for redirect in redirect_uris:
            if self.redirect_uri_is_global_wildcard(redirect):
                yield self.generate_finding(
                    client, additional_details={"redirect_uri": redirect, "public_client": client.is_public()}
                )
