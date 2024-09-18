from kcwarden.api import Auditor
from kcwarden.custom_types.result import Severity


class ClientWithFullScopeAllowed(Auditor):
    DEFAULT_SEVERITY = Severity.Info
    SHORT_DESCRIPTION = "Client has 'full scope allowed' set"
    LONG_DESCRIPTION = "Keycloak scopes control what information and roles are added to an access token. Generally, access tokens should be 'least privilege', meaning that they only contain the roles and information that are actually required to achieve the task. If the 'Full scope allowed' option is set on a client, it ignores the configured scopes, and simply adds all roles that the user has to the token, as if all scopes were selected. This leads to overprivileged tokens."
    REFERENCE = ""

    def should_consider_client(self, client) -> bool:
        return (
            self.is_not_ignored(client)
            and client.allows_user_authentication()
            and not client.is_realm_specific_client()
        )

    def client_has_full_scope_allowed(self, client) -> bool:
        return client.has_full_scope_allowed()

    def audit(self):
        for client in self._DB.get_all_clients():
            # Report clients with full scope allowed
            if self.should_consider_client(client):
                if self.client_has_full_scope_allowed(client):
                    yield self.generate_finding(
                        client,
                        additional_details={
                            "default_scopes": client.get_default_client_scopes(),
                            "optional_scopes": client.get_optional_client_scopes(),
                        },
                    )
