from kcwarden.api import Auditor
from kcwarden.custom_types.result import Severity

class SamlEncryptCheck(Auditor):
    DEFAULT_SEVERITY = Severity.High
    SHORT_DESCRIPTION = "SAML Assertion encryption is disabled"
    LONG_DESCRIPTION = "The SAML Assertion is sent in cleartext (Base64 encoded only). This allows intermediaries to read PII and facilitates XML Signature Wrapping (XSW) attacks."
    REFERENCE = ""

    def should_consider_client(self, client) -> bool:
        if not self.is_not_ignored(client):
            return False
            
        protocol = client.get_protocol()
        return protocol == "saml"

    @staticmethod
    def is_vulnerable(client) -> bool:
        attributes = client.get_attributes()
        # Check for saml.encrypt
        val = attributes.get("saml.encrypt", "false")
        return val != "true"

    def audit(self):
        for client in self._DB.get_all_clients():
            if self.should_consider_client(client):
                if self.is_vulnerable(client):
                    yield self.generate_finding(client)