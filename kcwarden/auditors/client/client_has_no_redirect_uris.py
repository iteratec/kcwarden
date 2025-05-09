from kcwarden.api import Auditor
from kcwarden.custom_types.keycloak_object import Client
from kcwarden.custom_types.result import Severity


class ClientHasNoRedirectUris(Auditor):
    DEFAULT_SEVERITY = Severity.Medium
    SHORT_DESCRIPTION = "Missing client redirect URIs can cause unexpected behavior"
    LONG_DESCRIPTION = (
        "The list of allowed redirect URIs is unexpectedly empty. Using Keycloak's administration UI, "
        "this is not even possible to set (only via direct admin API calls). "
        "The security of the OIDC standard flow and others rely on the allowed redirect URIs,"
        " and thus Keycloak has a fallback mechanism (involving e.g. the root URL). "
        "This behavior is not emulated by kcwarden, "
        "and thus other auditors do not produce correct findings. "
        "In addition, Keycloak's fallback mechanism might change over time and can lead to unexpected behavior. "
        "It is highly recommended to explicitly set the redirect URIs for this client."
    )
    REFERENCE = ""

    def should_consider_client(self, client: Client) -> bool:
        # We are interested in clients that are:
        # - OIDC Clients
        # - At least one flow that uses the redirect_uri active
        # TODO Are there more flows that use redirect_uri?
        return (
            self.is_not_ignored(client)
            and not client.is_default_keycloak_client()
            and not client.is_realm_specific_client()
            and client.is_oidc_client()
            and (client.has_standard_flow_enabled() or client.has_implicit_flow_enabled())
        )

    def audit(self):
        for client in self._DB.get_all_clients():
            if self.should_consider_client(client):
                redirect_uris = client.get_resolved_redirect_uris()

                if len(redirect_uris) == 0:
                    yield self.generate_finding(client)
