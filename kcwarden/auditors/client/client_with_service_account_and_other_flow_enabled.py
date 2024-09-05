from kcwarden.api import Auditor
from kcwarden.custom_types.result import Severity


class ClientWithServiceAccountAndOtherFlowEnabled(Auditor):
    DEFAULT_SEVERITY = Severity.Info
    SHORT_DESCRIPTION = "Confidential Client with Service Accounts and other flow enabled"
    LONG_DESCRIPTION = "Often, confidential clients that have service accounts associated with them are exclusively used for their service account. In these cases, any additional methods (standard flow, implicit flow, ...) can be disabled as a matter of general hygene. If you are using both features of the client, feel free to ignore this finding."
    REFERENCE = ""

    def should_consider_client(self, client) -> bool:
        # We are interested in clients that are:
        # - OIDC Clients
        # - Confidential
        # - Has service account
        return (
            self.is_not_ignored(client)
            and client.is_oidc_client()
            and (not client.is_public())
            and client.has_service_account_enabled()
        )

    def client_has_non_service_account_flow_enabled(self, client):
        # If this client has any other flows enabled, emit an informational finding
        # TODO Are there any other flows that could be enabled?
        return client.allows_user_authentication()

    def audit(self):
        for client in self._DB.get_all_clients():
            if self.should_consider_client(client):
                if self.client_has_non_service_account_flow_enabled(client):
                    yield self.generate_finding(
                        client,
                        additional_details={
                            "client_public": client.is_public(),
                            "service_account_enabled": client.has_service_account_enabled(),
                            "standard_flow_enabled": client.has_standard_flow_enabled(),
                            "implicit_flow_enabled": client.has_implicit_flow_enabled(),
                            "direct_access_grant_enabled": client.has_direct_access_grants_enabled(),
                            "device_flow_enabled": client.has_device_authorization_grant_flow_enabled(),
                        },
                    )
