from kcwarden.api import Auditor
from kcwarden.custom_types.result import Severity

class SamlClientWeakAlgorithmCheck(Auditor):
    DEFAULT_SEVERITY = Severity.Medium
    SHORT_DESCRIPTION = "Weak SAML Signature Algorithm detected"
    LONG_DESCRIPTION = "The client is configured to use RSA_SHA1 or DSA_SHA1. These algorithms are considered weak and vulnerable to collision attacks."
    REFERENCE = ""

    def should_consider_client(self, client) -> bool:
        return self.is_not_ignored(client) and client.get_protocol() == "saml"

    @staticmethod
    def is_vulnerable(client) -> bool:
        attributes = client.get_attributes()
        algo = attributes.get("saml.signature.algorithm", "")
        weak_algos = ["RSA_SHA1", "DSA_SHA1"]
        
        return algo in weak_algos

    def audit(self):
        for client in self._DB.get_all_clients():
            if self.should_consider_client(client):
                if self.is_vulnerable(client):
                    attributes = getattr(client, "attributes", client.get("attributes", {}))
                    algo = attributes.get("saml.signature.algorithm", "Unknown")
                    
                    yield self.generate_finding(client, additional_details={"detected_algorithm": algo})