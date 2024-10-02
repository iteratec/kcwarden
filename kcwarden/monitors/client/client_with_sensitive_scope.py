from kcwarden.api import Monitor
from kcwarden.custom_types.result import Severity
from kcwarden.database import helper


class ClientWithSensitiveScope(Monitor):
    """Checks for the use of sensitive scopes.

    In some situations, specific scopes should only be available for specific clients.
    This Auditor checks which OIDC clients have a specific scope in their default or
    optional scopes. You can define which clients you would expect to have access to
    this scope in the config file. All other clients that have the scope are reported.

    If no scopes are defined in the config file, this auditor will not run.
    """

    DEFAULT_SEVERITY = Severity.Medium
    SHORT_DESCRIPTION = "Unexpected client uses monitored sensitive scope"
    LONG_DESCRIPTION = "In the configuration, you have defined this scope to be sensitive, and defined a set of expected clients that are allowed to use it. An unexpected client has been detected that has been assigned this scope as either optional or default scope. If this is expected, please add it to the allowlist in the configuration file."
    REFERENCE = ""
    HAS_CUSTOM_CONFIG = True
    CUSTOM_CONFIG_TEMPLATE = {
        "scope": "scope name or regular expression",
    }

    def audit(self):
        custom_config = self.get_custom_config()
        for monitor_definition in custom_config:
            # Load config
            monitored_scope: str = monitor_definition["scope"]
            allowed_clients: list[str] = monitor_definition["allowed"]
            # Skip default config entry, in case it was still present
            if monitored_scope == self.CUSTOM_CONFIG_TEMPLATE["scope"]:  # type: ignore - confused linter
                continue
            for client in self._DB.get_all_clients():
                # if self.is_not_ignored(client) and (monitored_scope in client.get_default_client_scopes() or monitored_scope in client.get_optional_client_scopes()):
                if self.is_not_ignored(client) and (
                    helper.regex_matches_list_entry(monitored_scope, client.get_default_client_scopes())
                    or helper.regex_matches_list_entry(monitored_scope, client.get_optional_client_scopes())
                ):
                    if not helper.matches_list_of_regexes(client.get_name(), allowed_clients):
                        yield self.generate_finding_with_severity_from_config(
                            client,
                            monitor_definition,
                            additional_details={
                                "monitored_scope": monitored_scope,
                                "default_scopes": client.get_default_client_scopes(),
                                "optional_scopes": client.get_optional_client_scopes(),
                            },
                        )
