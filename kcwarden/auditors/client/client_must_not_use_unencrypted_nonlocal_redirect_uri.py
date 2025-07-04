import urllib.parse

from kcwarden.api.auditor import ClientAuditor
from kcwarden.custom_types.keycloak_object import Client
from kcwarden.custom_types.result import Severity


class ClientMustNotUseUnencryptedNonlocalRedirectUri(ClientAuditor):
    DEFAULT_SEVERITY = Severity.Medium
    SHORT_DESCRIPTION = "Authorization Responses MUST NOT be transmitted via unencrypted connections"
    LONG_DESCRIPTION = "Authorization responses contain sensitive data, like the OAuth Response Code, which should not be exposed. Therefore, the redirect_uri MUST be set to a HTTPS URI or (for native apps) a localhost address."
    REFERENCE = "https://datatracker.ietf.org/doc/html/rfc9700#section-2.6"

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
    def redirect_uri_is_http_and_non_local(redirect) -> bool:
        # Parse the redirect URI as a URL
        parsed_redirect_uri = urllib.parse.urlparse(redirect)
        # We only consider those URLs that are explicitly recognized as http.
        # There are several cases where this will not happen, for example, if URLs
        # are defined relative to the base URL of keycloak, which cannot be determined
        # based on the config dumps.
        # In these cases, we do not match them in this rule. Instead, we have a separate
        # Auditor that emits informational findings for these cases.
        # Unencrypted connections to a `localhost` address are permitted.
        # All others should be reported
        return parsed_redirect_uri.scheme == "http" and parsed_redirect_uri.hostname not in [
            "localhost",
            "127.0.0.1",
            "::1",
        ]

    def audit_client(self, client: Client):
        redirect_uris = client.get_resolved_redirect_uris()

        # Run checks for every redirect URI
        for redirect in redirect_uris:
            if self.redirect_uri_is_http_and_non_local(redirect):
                yield self.generate_finding(client, additional_details={"redirect_uri": redirect})
