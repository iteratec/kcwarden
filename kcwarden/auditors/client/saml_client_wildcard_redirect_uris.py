from kcwarden.api import Auditor
from kcwarden.custom_types.result import Severity

class SamlClientWildcardRedirectUriCheck(Auditor):
    DEFAULT_SEVERITY = Severity.Medium
    SHORT_DESCRIPTION = "Client allows wildcard redirect URIs"
    LONG_DESCRIPTION = "The client configuration contains a wildcard (*) at the end of a Redirect URI. This allows open redirects to subdirectories, potentially leading to token theft."
    REFERENCE = ""

    def should_consider_client(self, client) -> bool:
        return self.is_not_ignored(client) and client.is_saml_client()

    def get_vulnerable_uris(self, client) -> list[str]:
        uris = client.get_resolved_redirect_uris()
        if not uris:
            return []
        return [uri for uri in uris if uri and uri.strip().endswith("*")]

    def audit(self):
        for client in self._DB.get_all_clients():
            if self.should_consider_client(client):
                bad_uris = self.get_vulnerable_uris(client)
                if bad_uris:
                    yield self.generate_finding(
                        client, 
                        additional_details={"vulnerable_uris": bad_uris}
                    )