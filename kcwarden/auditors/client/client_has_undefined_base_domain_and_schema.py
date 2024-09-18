import urllib.parse

from kcwarden.api import Auditor
from kcwarden.custom_types.result import Severity


class ClientHasUndefinedBaseDomainAndSchema(Auditor):
    DEFAULT_SEVERITY = Severity.Info
    SHORT_DESCRIPTION = "Client redirect URL scheme undefined, cannot be audited"
    LONG_DESCRIPTION = "Authorization responses contain sensitive data, like the OAuth Response Code, which should not be exposed. Therefore, the redirect_uri MUST be set to a HTTPS URI or (for native apps) a localhost address. For this client, this rule could not be validated, as the redirect URI combined with the root URL is insufficient to determine the used scheme. In most cases, this means that no clear redirect URI is defined. To remediate, define a fully qualified domain name including scheme (e.g. 'https://example.com/login') for either the client root URL or the redirect URI(s)."
    REFERENCE = "https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics-23#section-2.6"

    def should_consider_client(self, client) -> bool:
        # We are interested in clients that are:
        # - OIDC Clients
        # - At least one flow that uses the redirect_uri active
        # TODO Are there more flows that use redirect_uri?
        return (
            self.is_not_ignored(client)
            and not client.is_realm_specific_client()
            and client.is_oidc_client()
            and (client.has_standard_flow_enabled() or client.has_implicit_flow_enabled())
        )

    def redirect_uri_has_empty_scheme(self, redirect) -> bool:
        parsed_redirect_uri = urllib.parse.urlparse(redirect)
        return parsed_redirect_uri.scheme == ""

    def audit(self):
        for client in self._DB.get_all_clients():
            if self.should_consider_client(client):
                redirect_uris = client.get_resolved_redirect_uris()
                for redirect in redirect_uris:
                    if self.redirect_uri_has_empty_scheme(redirect):
                        # The redirect URI is insufficiently specified to determine the URI scheme.
                        yield self.generate_finding(client, additional_details={"redirect_uri": redirect})
