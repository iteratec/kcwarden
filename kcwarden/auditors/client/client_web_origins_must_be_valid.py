import urllib.parse

from kcwarden.api.auditor import ClientAuditor
from kcwarden.custom_types.keycloak_object import Client
from kcwarden.custom_types.result import Severity

# Keycloak-specific special values that are not URLs but are valid webOrigins entries
_KEYCLOAK_SPECIAL_ORIGINS = {"+", "*"}


class ClientWebOriginsMustBeValid(ClientAuditor):
    DEFAULT_SEVERITY = Severity.Info
    SHORT_DESCRIPTION = "Client has an invalid webOrigins entry"
    LONG_DESCRIPTION = (
        "The webOrigins setting controls which origins are allowed for CORS requests. "
        "Each entry must be a valid origin of the form scheme://host or scheme://host:port, "
        "without a path, query string, or fragment. Invalid entries are silently ignored by "
        "Keycloak, which may lead to unexpected CORS behaviour."
    )
    REFERENCE = "https://datatracker.ietf.org/doc/html/rfc6454#section-3.2"

    @staticmethod
    def is_valid_origin(value: str) -> bool:
        if value in _KEYCLOAK_SPECIAL_ORIGINS or value == "":
            return True
        parsed = urllib.parse.urlparse(value)
        # Must have a scheme and a host; must not have a path, query, or fragment
        return (
            bool(parsed.scheme)
            and bool(parsed.netloc)
            and parsed.path == ""
            and not parsed.query
            and not parsed.fragment
        )

    def audit_client(self, client: Client):
        for origin in client.get_web_origins():
            if not self.is_valid_origin(origin):
                yield self.generate_finding(client, additional_details={"web_origin": origin})
