from kcwarden.api.auditor import ClientAuditor
from kcwarden.auditors.client.client_has_erroneously_configured_wildcard_uri import (
    ClientHasErroneouslyConfiguredWildcardURI,
)
from kcwarden.custom_types.keycloak_object import Client
from kcwarden.custom_types.result import Severity


class SamlClientHasErroneouslyConfiguredWildcardURI(ClientAuditor):
    DEFAULT_SEVERITY = Severity.Critical
    SHORT_DESCRIPTION = "Erroneously configured redirect URI allows arbitrary domains for redirects"
    LONG_DESCRIPTION = "The client has a SAML Assertion Consumer Service (ACS) URL where the wildcard appears in the domain part of the URI (e.g., https://example.com*) rather than after a path delimiter (e.g., https://example.com/*). This is almost certainly a misconfiguration. Keycloak uses the configured ACS URLs as an allowlist to validate where SAML assertions may be sent. A wildcard in the domain position allows any domain that begins with the specified prefix to match (e.g., https://example.com.attacker.tk), enabling an attacker to redirect SAML assertions to an arbitrary server and steal the victim's session."
    REFERENCE = ""

    def should_consider_client(self, client: Client) -> bool:
        return super().should_consider_client(client) and client.is_saml_client()

    def audit_client(self, client: Client):
        for uri in client.get_resolved_redirect_uris():
            # Recycle the implementation of the OIDC check for this, as we assume the logic inside Keycloak is the same.
            if ClientHasErroneouslyConfiguredWildcardURI.redirect_uri_has_wildcard_in_domain(uri):
                yield self.generate_finding(client, additional_details={"redirect_uri": uri})
