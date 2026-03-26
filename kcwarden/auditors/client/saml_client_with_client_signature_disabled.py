from kcwarden.api.auditor import ClientAuditor
from kcwarden.custom_types.keycloak_object import Client
from kcwarden.custom_types.result import Severity


class SamlClientWithClientSignatureDisabled(ClientAuditor):
    DEFAULT_SEVERITY = Severity.High
    SHORT_DESCRIPTION = "SAML Client AuthnRequest signature not required"
    LONG_DESCRIPTION = "Keycloak is configured not to verify the digital signature of the AuthnRequest sent by the Service Provider. This risks AuthnRequest Spoofing and Login CSRF."
    REFERENCE = ""

    def should_consider_client(self, client: Client) -> bool:
        return super().should_consider_client(client) and client.is_saml_client()

    def audit_client(self, client: Client):
        if not client.is_saml_client_signature_required():
            yield self.generate_finding(client)
