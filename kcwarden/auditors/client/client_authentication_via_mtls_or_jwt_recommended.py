from kcwarden.api import Auditor
from kcwarden.custom_types.result import Severity


class ClientAuthenticationViaMTLSOrJWTRecommended(Auditor):
    DEFAULT_SEVERITY = Severity.Info
    SHORT_DESCRIPTION = "Client Authentication via mTLS or Signed JWT is Recommended"
    LONG_DESCRIPTION = "Confidential Clients need to authenticate to Keycloak to use its features. By default, is uses a shared client secret. It is RECOMMENDED to use mTLS or signed JWTs instead, if possible. For details, see the Keycloak documentation: https://www.keycloak.org/docs/latest/server_admin/#_client-credentials"
    REFERENCE = "https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics-23#section-2.5"

    def should_consider_client(self, client) -> bool:
        # We are interested in clients that are:
        # - OIDC Clients
        # - Confidential Clients
        return (
            self.is_not_ignored(client)
            and not client.is_realm_specific_client()
            and client.is_oidc_client()
            and not client.is_public()
        )

    def client_does_not_use_mtls_or_jwt_auth(self, client) -> bool:
        # If the clientAuthenticatorType is client-secret, basic client secret authentication is used.
        # TODO Check what the correct values for mTLS or signed JWT are, and update this check
        return client.get_client_authenticator_type() == "client-secret"

    def audit(self):
        for client in self._DB.get_all_clients():
            if self.should_consider_client(client):
                if self.client_does_not_use_mtls_or_jwt_auth(client):
                    # All clients matching these criteria should be reported
                    yield self.generate_finding(client)
