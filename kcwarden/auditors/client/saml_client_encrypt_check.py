from kcwarden.api.auditor import ClientAuditor
from kcwarden.custom_types.keycloak_object import Client
from kcwarden.custom_types.result import Severity


class SamlClientEncryptCheck(ClientAuditor):
    DEFAULT_SEVERITY = Severity.High
    SHORT_DESCRIPTION = "SAML Assertion encryption is disabled"
    LONG_DESCRIPTION = "The SAML Assertion is sent in cleartext (Base64 encoded only). This allows intermediaries to read PII and facilitates XML Signature Wrapping (XSW) attacks."
    REFERENCE = ""

    def should_consider_client(self, client: Client) -> bool:
        return super().should_consider_client(client) and client.is_saml_client()

    def audit_client(self, client: Client):
        if not client.is_saml_encryption_enabled():
            yield self.generate_finding(client)
