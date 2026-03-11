from kcwarden.api import Auditor
from kcwarden.custom_types.result import Severity

class SamlClientSignatureCheck(Auditor):
    DEFAULT_SEVERITY = Severity.High
    SHORT_DESCRIPTION = "SAML Client AuthnRequest signature not required"
    LONG_DESCRIPTION = "Keycloak is configured not to verify the digital signature of the AuthnRequest sent by the Service Provider. This risks AuthnRequest Spoofing and Login CSRF."
    REFERENCE = ""

    def should_consider_client(self, client) -> bool:
        return self.is_not_ignored(client) and client.is_saml_client()

    def audit(self):
        for client in self._DB.get_all_clients():
            if self.should_consider_client(client):
                if not client.is_saml_client_signature_required():
                    yield self.generate_finding(client)