from kcwarden.api import Auditor
from kcwarden.custom_types.result import Severity

class SamlClientWeakAlgorithmCheck(Auditor):
    DEFAULT_SEVERITY = Severity.Medium
    SHORT_DESCRIPTION = "Weak SAML Signature Algorithm detected"
    LONG_DESCRIPTION = "The client is configured to use RSA_SHA1 or DSA_SHA1. These algorithms are considered weak and vulnerable to collision attacks."
    REFERENCE = ""

    WEAK_ALGORITHMS = ["RSA_SHA1", "DSA_SHA1"]

    def should_consider_client(self, client) -> bool:
        return self.is_not_ignored(client) and client.is_saml_client()

    def audit(self):
        for client in self._DB.get_all_clients():
            if self.should_consider_client(client):
                algo = client.get_saml_signature_algorithm()
                
                if algo in self.WEAK_ALGORITHMS:
                    yield self.generate_finding(
                        client, 
                        additional_details={"detected_algorithm": algo}
                    )