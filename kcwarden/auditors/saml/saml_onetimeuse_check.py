from kcwarden.api import Auditor
from kcwarden.custom_types.result import Severity

class SamlOneTimeUseCheck(Auditor):
    DEFAULT_SEVERITY = Severity.Medium
    SHORT_DESCRIPTION = "SAML OneTimeUse condition not enabled"
    LONG_DESCRIPTION = "Keycloak is not configured to add the <OneTimeUse> condition to SAML Assertions. This increases the risk of Replay Attacks if the Service Provider does not strictly track Assertion IDs."
    REFERENCE = ""

    def should_consider_client(self, client) -> bool:
        if not self.is_not_ignored(client):
            return False
            
        if hasattr(client, "get_protocol"):
            protocol = client.get_protocol()
        elif hasattr(client, "get"):
            protocol = client.get("protocol")
        else:
            protocol = getattr(client, "protocol", None)

        return protocol == "saml"

    @staticmethod
    def is_vulnerable(client) -> bool:
        if hasattr(client, "get_attributes"):
            attributes = client.get_attributes()
        elif hasattr(client, "get"):
            attributes = client.get("attributes", {})
        else:
            attributes = getattr(client, "attributes", {})

        # Check for saml.onetimeuse.condition
        val = attributes.get("saml.onetimeuse.condition", "false")
        return val != "true"

    def audit(self):
        for client in self._DB.get_all_clients():
            if self.should_consider_client(client):
                if self.is_vulnerable(client):
                    yield self.generate_finding(client)