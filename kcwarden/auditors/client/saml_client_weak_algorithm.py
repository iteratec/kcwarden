from kcwarden.api.auditor import ClientAuditor
from kcwarden.custom_types.keycloak_object import Client
from kcwarden.custom_types.result import Severity


class SamlClientWeakAlgorithmCheck(ClientAuditor):
    DEFAULT_SEVERITY = Severity.Medium
    SHORT_DESCRIPTION = "Weak SAML Signature Algorithm detected"
    LONG_DESCRIPTION = "The client is configured to use RSA_SHA1 or DSA_SHA1. These algorithms are considered weak and vulnerable to collision attacks."
    REFERENCE = ""

    WEAK_ALGORITHMS = ["RSA_SHA1", "DSA_SHA1"]

    def should_consider_client(self, client: Client) -> bool:
        return super().should_consider_client(client) and client.is_saml_client()

    def audit_client(self, client: Client):
        algo = client.get_saml_signature_algorithm()
        if algo in self.WEAK_ALGORITHMS:
            yield self.generate_finding(client, additional_details={"detected_algorithm": algo})
