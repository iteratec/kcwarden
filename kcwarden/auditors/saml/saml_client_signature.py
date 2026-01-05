from kcwarden.api import Auditor
from kcwarden.custom_types.result import Severity

class SamlClientSignatureCheck(Auditor):
    DEFAULT_SEVERITY = Severity.High
    SHORT_DESCRIPTION = "SAML Client AuthnRequest signature not required"
    LONG_DESCRIPTION = "Keycloak is configured not to verify the digital signature of the AuthnRequest sent by the Service Provider. This risks AuthnRequest Spoofing and Login CSRF."
    REFERENCE = ""

    def should_consider_client(self, client) -> bool:
        if not self.is_not_ignored(client):
            return False
            
        protocol = client.get_protocol()
        return protocol == "saml"

    @staticmethod
    def is_vulnerable(client) -> bool:
        attributes = client.get_attributes()
        # Default is often false if missing, or explicitly set to false
        val = attributes.get("saml.client.signature", "false")
        return val != "true"

    def audit(self):
        for client in self._DB.get_all_clients():
            if self.should_consider_client(client):
                if self.is_vulnerable(client):
                    yield self.generate_finding(client)