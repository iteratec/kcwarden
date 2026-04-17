from kcwarden.api.auditor import ClientAuditor
from kcwarden.custom_types.keycloak_object import Client
from kcwarden.custom_types.result import Severity


class SamlClientShouldNotUseWildcardRedirectURI(ClientAuditor):
    DEFAULT_SEVERITY = Severity.Medium
    SHORT_DESCRIPTION = "Client allows wildcard redirect URIs"
    LONG_DESCRIPTION = "The client configuration contains a wildcard (*) at the end of a Redirect URI. This allows open redirects to subdirectories, potentially leading to token theft."
    REFERENCE = ""

    def should_consider_client(self, client: Client) -> bool:
        return super().should_consider_client(client) and client.is_saml_client()

    def get_vulnerable_uris(self, client: Client) -> list[str]:
        uris = client.get_resolved_redirect_uris()
        if not uris:
            return []
        return [uri for uri in uris if uri[-1:] == "*"]

    def audit_client(self, client: Client):
        for uri in self.get_vulnerable_uris(client):
            yield self.generate_finding(client, additional_details={"redirect_uri": uri})
