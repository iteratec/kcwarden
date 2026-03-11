from kcwarden.api import Auditor
from kcwarden.custom_types.result import Severity

class SamlClientOneTimeUseCheck(Auditor):
    DEFAULT_SEVERITY = Severity.Medium
    SHORT_DESCRIPTION = "SAML OneTimeUse condition not enabled"
    LONG_DESCRIPTION = "Keycloak is not configured to add the <OneTimeUse> condition to SAML Assertions. This increases the risk of Replay Attacks if the Service Provider does not strictly track Assertion IDs."
    REFERENCE = ""

    def should_consider_client(self, client) -> bool:
        return self.is_not_ignored(client) and client.is_saml_client()

    def audit(self):
        for client in self._DB.get_all_clients():
            if self.should_consider_client(client):
                if not client.is_saml_onetimeuse_condition_enabled():
                    yield self.generate_finding(client)