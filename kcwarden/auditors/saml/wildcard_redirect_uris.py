from kcwarden.api import Auditor
from kcwarden.custom_types.result import Severity

class WildcardRedirectUriCheck(Auditor):
    DEFAULT_SEVERITY = Severity.Medium
    SHORT_DESCRIPTION = "Client allows wildcard redirect URIs"
    LONG_DESCRIPTION = "The client configuration contains a wildcard (*) at the end of a Redirect URI. This allows open redirects to subdirectories, potentially leading to token theft."
    REFERENCE = ""

    def should_consider_client(self, client) -> bool:
        if not self.is_not_ignored(client):
            return False
        
        return True

    def is_vulnerable(self, client) -> bool:
        uris = client.get_redirect_uris()

        if not uris:
            return False

        for uri in uris:
            # Check for trailing wildcard
            if uri and uri.strip().endswith("*"):
                return True
        return False

    def audit(self):
        for client in self._DB.get_all_clients():
            if self.should_consider_client(client):
                if self.is_vulnerable(client):
                    # Re-fetch URIs for the report detail
                    uris = client.get_redirect_uris()
                    bad_uris = [u for u in uris if u.endswith("*")]
                    
                    yield self.generate_finding(
                        client, 
                        additional_details={"vulnerable_uris": bad_uris}
                    )