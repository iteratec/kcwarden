import urllib.parse

from kcwarden.api import Auditor
from kcwarden.custom_types.keycloak_object import Client
from kcwarden.custom_types.result import Severity


class ClientUsesCustomRedirectUriScheme(Auditor):
    DEFAULT_SEVERITY = Severity.Info
    SHORT_DESCRIPTION = "Client redirect URL scheme uses custom protocol"
    # noinspection HttpUrlsUsage
    LONG_DESCRIPTION = (
        "Authorization responses contain sensitive data, like the OAuth Response Code, which should "
        "not be exposed. This client uses a custom protocol (i.e., not http:// or https://), "
        "which should be closely inspected. Note that the use of custom protocols can pose a security "
        "risk when used to connect to a mobile app on a smartphone. See the online documentation for "
        "more information."
    )
    REFERENCE = ""

    def should_consider_client(self, client: Client) -> bool:
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

    @staticmethod
    def redirect_uri_uses_custom_protocol(redirect: str) -> bool:
        # Parse as a URL to get access to the scheme
        parsed_redirect_uri = urllib.parse.urlparse(redirect)
        # http connections are covered by ClientMustNotUseUnencryptedNonlocalRedirectUri.
        # https connections are permitted.
        # Empty scheme would indicate that a relative address is provided, and we can't make any statements
        # All others are suspect and should be reported.
        return parsed_redirect_uri.scheme not in ["http", "https", ""]

    def audit(self):
        for client in self._DB.get_all_clients():
            if self.should_consider_client(client):
                redirect_uris = client.get_resolved_redirect_uris()

                for redirect in redirect_uris:
                    if self.redirect_uri_uses_custom_protocol(redirect):
                        yield self.generate_finding(client, additional_details={"redirect_uri": redirect})
