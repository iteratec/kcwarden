from kcwarden.api.auditor import ClientAuditor
from kcwarden.custom_types.keycloak_object import Client
from kcwarden.custom_types.result import Severity


class ClientWithFullScopeAllowed(ClientAuditor):
    DEFAULT_SEVERITY = Severity.Info
    SHORT_DESCRIPTION = "Client has 'full scope allowed' set"
    LONG_DESCRIPTION = "Keycloak scopes control what information and roles are added to an access token. Generally, access tokens should be 'least privilege', meaning that they only contain the roles and information that are actually required to achieve the task. If the 'Full scope allowed' option is set on a client, it ignores the configured scopes, and simply adds all roles that the user has to the token, as if all scopes were selected. This leads to overprivileged tokens."
    REFERENCE = ""

    def should_consider_client(self, client) -> bool:
        return (
            super().should_consider_client(client)
            and client.allows_user_authentication()
            and not client.is_realm_specific_client()
        )

    @staticmethod
    def client_has_full_scope_allowed(client) -> bool:
        return client.has_full_scope_allowed()

    def audit_client(self, client: Client):
        if self.client_has_full_scope_allowed(client):
            yield self.generate_finding(
                client,
                additional_details={
                    "default_scopes": client.get_default_client_scopes(),
                    "optional_scopes": client.get_optional_client_scopes(),
                },
            )
