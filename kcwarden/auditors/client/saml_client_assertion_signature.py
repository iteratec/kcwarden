from kcwarden.api import Auditor
from kcwarden.custom_types.result import Severity

class SamlClientAssertionSignatureCheck(Auditor):
    DEFAULT_SEVERITY = Severity.High
    SHORT_DESCRIPTION = "SAML Assertion block is not signed"
    LONG_DESCRIPTION = "Keycloak issues tokens without signing the Assertion block. This allows attackers to modify the NameID (username) or Roles in the XML to commit Token Forgery."
    REFERENCE = ""

    def should_consider_client(self, client) -> bool:
        return self.is_not_ignored(client) and client.is_saml_client()

    def audit(self):
        for client in self._DB.get_all_clients():
            if self.should_consider_client(client):
                if not client.get_saml_assertion_signature():
                    yield self.generate_finding(client)