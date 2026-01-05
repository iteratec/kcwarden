from kcwarden.api import Auditor
from kcwarden.custom_types.result import Severity

class SamlClientAssertionSignatureCheck(Auditor):
    DEFAULT_SEVERITY = Severity.High
    SHORT_DESCRIPTION = "SAML Assertion block is not signed"
    LONG_DESCRIPTION = "Keycloak issues tokens without signing the Assertion block. This allows attackers to modify the NameID (username) or Roles in the XML to commit Token Forgery."
    REFERENCE = ""

    def should_consider_client(self, client) -> bool:
        return self.is_not_ignored(client) and client.get_protocol() == "saml"

    @staticmethod
    def is_vulnerable(client) -> bool:
        attributes = client.get_attributes()
        val = attributes.get("saml.assertion.signature", "false")
        return val != "true"

    def audit(self):
        for client in self._DB.get_all_clients():
            if self.should_consider_client(client):
                if self.is_vulnerable(client):
                    yield self.generate_finding(client)