from kcwarden.api.auditor import ClientAuditor
from kcwarden.custom_types.keycloak_object import Client
from kcwarden.custom_types.result import Severity


class SamlClientAssertionSignatureCheck(ClientAuditor):
    DEFAULT_SEVERITY = Severity.High
    SHORT_DESCRIPTION = "SAML Assertion block is not signed"
    LONG_DESCRIPTION = "Keycloak issues tokens without signing the Assertion block. This allows attackers to modify the NameID (username) or Roles in the XML to commit Token Forgery."
    REFERENCE = ""

    def should_consider_client(self, client: Client) -> bool:
        return super().should_consider_client(client) and client.is_saml_client()

    def audit_client(self, client: Client):
        if not client.get_saml_assertion_signature():
            yield self.generate_finding(client)
