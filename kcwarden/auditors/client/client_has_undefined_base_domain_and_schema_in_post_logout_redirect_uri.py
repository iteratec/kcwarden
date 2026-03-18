import urllib.parse

from kcwarden.api.auditor import ClientAuditor
from kcwarden.custom_types.keycloak_object import Client
from kcwarden.custom_types.result import Severity

# Keycloak special value: inherit post-logout redirect URIs from the client's redirect URIs
_KEYCLOAK_INHERIT = "+"


class ClientHasUndefinedBaseDomainAndSchemaInPostLogoutRedirectUri(ClientAuditor):
    DEFAULT_SEVERITY = Severity.Info
    SHORT_DESCRIPTION = "Client post-logout redirect URI scheme undefined, cannot be audited"
    LONG_DESCRIPTION = (
        "After an RP-initiated logout, the OpenID Provider redirects the user back to the Relying Party "
        "using a URI from the client's registered post_logout_redirect_uris. "
        "According to the OIDC RP-Initiated Logout specification, these URIs should use the HTTPS scheme "
        "and must not contain a fragment component. "
        "For this client, the scheme of a post-logout redirect URI could not be determined, because the URI "
        "combined with the client's root URL does not resolve to a fully qualified address. "
        "An unresolvable URI cannot be safely used for post-logout redirection and will silently fail. "
        "To remediate, define a fully qualified URI including scheme "
        "(e.g. 'https://example.com/logout') for the post_logout_redirect_uris or the client root URL."
    )
    REFERENCE = "https://openid.net/specs/openid-connect-rpinitiated-1_0.html#RedirectionAfterLogout"

    def should_consider_client(self, client: Client) -> bool:
        return (
            super().should_consider_client(client) and not client.is_realm_specific_client() and client.is_oidc_client()
        )

    @staticmethod
    def post_logout_redirect_uri_has_empty_scheme(uri: str) -> bool:
        return urllib.parse.urlparse(uri).scheme == ""

    def audit_client(self, client: Client):
        for uri in client.get_resolved_post_logout_redirect_uris():
            if uri == _KEYCLOAK_INHERIT:
                continue
            if self.post_logout_redirect_uri_has_empty_scheme(uri):
                yield self.generate_finding(client, additional_details={"post_logout_redirect_uri": uri})
