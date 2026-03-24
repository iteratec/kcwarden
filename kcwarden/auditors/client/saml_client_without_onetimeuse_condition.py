from kcwarden.api.auditor import ClientAuditor
from kcwarden.custom_types.keycloak_object import Client
from kcwarden.custom_types.result import Severity


class SamlClientWithoutOneTimeUseCondition(ClientAuditor):
    DEFAULT_SEVERITY = Severity.Medium
    SHORT_DESCRIPTION = "SAML OneTimeUse condition not enabled"
    LONG_DESCRIPTION = "Keycloak is not configured to add the <OneTimeUse> condition to SAML Assertions. This increases the risk of Replay Attacks if the Service Provider does not strictly track Assertion IDs."
    REFERENCE = ""

    def should_consider_client(self, client: Client) -> bool:
        return super().should_consider_client(client) and client.is_saml_client()

    def audit_client(self, client: Client):
        if not client.is_saml_onetimeuse_condition_enabled():
            yield self.generate_finding(client)
