import urllib.parse

from kcwarden.api.auditor import ClientAuditor
from kcwarden.auditors.client.client_must_not_use_global_wildcard_uri import ClientMustNotUseGlobalWildcardURI
from kcwarden.custom_types.keycloak_object import Client
from kcwarden.custom_types.result import Severity


class ClientHasErroneouslyConfiguredWildcardURI(ClientAuditor):
    DEFAULT_SEVERITY = Severity.Critical
    SHORT_DESCRIPTION = "Erroneously configured redirect URI allows arbitrary domains for redirects"
    LONG_DESCRIPTION = "Authorization responses contain sensitive data, like the OAuth Response Code, which should not be exposed. Keycloak requires specifying an allowed set of redirect URIs. In this case, a redirect URI was specified that is almost certainly incorrect, as the domain name contains a wildcard in the domain name part (i.e., https://example.com*). This allows arbitrary domains to be specified as a redirect URI as long as they begin with the specified part of the redirect URI, e.g. example.com.attacker.tk. The wildcard should almost certainly be placed behind a slash to make it part of the Path (e.g., https://example.com/*)."
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
    def redirect_uri_has_wildcard_in_domain(redirect) -> bool:
        # Skip the findings that are caught by ClientMustNotUseGlobalWildcardURI
        if ClientMustNotUseGlobalWildcardURI.redirect_uri_is_global_wildcard(redirect):
            return False

        parsed_redirect_uri = urllib.parse.urlparse(redirect)
        # The redirect URI has the form https://domain.tld*
        if parsed_redirect_uri.scheme in ["https", "http"] and parsed_redirect_uri.netloc.endswith("*"):
            return True
        # If the protocol is missing, the domain is recognized as part of the path by urllib.
        # Workaround for these cases:
        # - URI scheme has to be empty
        # - netloc has to be empty (i.e., no domain was recognized)
        # - path does not contain a slash (i.e., we are not in the "real" path, but the path only contains the incorrectly specified Domain)
        # - path ends with wildcard (to trigger the vulnerability)
        # To be honest, I am not sure what Keycloak would do with data that is specified like this, and if it would even work.
        # However, I will flag it, just in case Keycloak is a bit too robust in dealing with these things.
        return (
            parsed_redirect_uri.scheme == ""
            and parsed_redirect_uri.netloc == ""
            and "/" not in parsed_redirect_uri.path
            and not redirect == "*"
            and parsed_redirect_uri.path.endswith("*")
        )

    def audit_client(self, client: Client):
        # These clients should use either a localhost or an HTTPS URI
        redirect_uris = client.get_resolved_redirect_uris()
        for redirect in redirect_uris:
            if self.redirect_uri_has_wildcard_in_domain(redirect):
                yield self.generate_finding(
                    client, additional_details={"redirect_uri": redirect, "public_client": client.is_public()}
                )
