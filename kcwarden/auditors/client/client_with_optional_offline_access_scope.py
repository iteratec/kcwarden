from kcwarden.api import Auditor
from kcwarden.custom_types.result import Severity


class ClientWithOptionalOfflineAccessScope(Auditor):
    DEFAULT_SEVERITY = Severity.Medium
    SHORT_DESCRIPTION = "Client has offline_access scope as optional scope"
    LONG_DESCRIPTION = "The 'offline_access' scope of Keycloak enables the use of offline tokens, which are a more powerful and long-lives version of refresh tokens. Having an offline token allows a user to keep a login session for a long time (depending on the server configuration - often half a year or longer). They are generally used for native applications (e.g., mobile apps) or server-to-server connections that need to be able to access a users' account while the user is not present. Other clients should not use this feature, as it is unnecessary, and because leaking an offline token to an attacker can allow them to gain long-term access to a users' account. Please check if this client really requires the use of offline tokens, and remove the scope, disable refresh tokens for this client, or add the client to the list of allowed clients in the kcwarden configuration to silence this warning."
    REFERENCE = ""

    def should_consider_client(self, client) -> bool:
        return self.is_not_ignored(client) and not client.is_realm_specific_client()

    def client_can_generate_offline_tokens(self, client) -> bool:
        # Check if the "offline_access" scope is in the optional scopes
        # But only report if a flow is activated that can actually give out offline tokens
        # and if refresh tokens are active on that client
        return (
            "offline_access" in client.get_optional_client_scopes()
            and client.allows_user_authentication()
            and client.get_attributes().get("use.refresh.tokens", "false") == "true"
        )

    def audit(self):
        for client in self._DB.get_all_clients():
            if self.should_consider_client(client):
                if self.client_can_generate_offline_tokens(client):
                    yield self.generate_finding(
                        client,
                        additional_details={
                            "default_scopes": client.get_default_client_scopes(),
                            "optional_scopes": client.get_optional_client_scopes(),
                            "client_public": client.is_public(),
                            "standard_flow_enabled": client.has_standard_flow_enabled(),
                            "implicit_flow_enabled": client.has_implicit_flow_enabled(),
                            "direct_access_grant_enabled": client.has_direct_access_grants_enabled(),
                            "device_flow_enabled": client.has_device_authorization_grant_flow_enabled(),
                        },
                    )
