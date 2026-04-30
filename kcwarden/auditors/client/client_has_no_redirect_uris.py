from kcwarden.api.auditor import ClientAuditor
from kcwarden.custom_types.keycloak_object import Client
from kcwarden.custom_types.result import Severity


class ClientHasNoRedirectUris(ClientAuditor):
    DEFAULT_SEVERITY = Severity.Medium
    SHORT_DESCRIPTION = "Missing client redirect URIs can cause unexpected behavior"
    LONG_DESCRIPTION = (
        "The list of allowed redirect URIs is unexpectedly empty. Using Keycloak's administration UI, "
        "this is not even possible to set (only via direct admin API calls). "
        "Keycloak will throw an error when trying to authenticate with this client using the Standard or Implicit flows."
    )
    REFERENCE = ""

    def should_consider_client(self, client: Client) -> bool:
        # We are interested in clients that are:
        # - OIDC Clients
        # - At least one flow that uses the redirect_uri active
        return (
            super().should_consider_client(client)
            and not client.is_default_keycloak_client()
            and not client.is_realm_specific_client()
            and client.is_oidc_client()
            and (client.has_standard_flow_enabled() or client.has_implicit_flow_enabled())
        )

    def audit_client(self, client: Client):
        redirect_uris = client.get_resolved_redirect_uris()

        if len(redirect_uris) == 0:
            yield self.generate_finding(client)
