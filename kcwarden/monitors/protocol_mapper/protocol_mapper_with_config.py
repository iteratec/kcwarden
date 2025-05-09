from typing import Any

from kcwarden.api import Monitor
from kcwarden.custom_types.keycloak_object import ProtocolMapper, Client
from kcwarden.custom_types.result import Severity
from kcwarden.database import helper


class ProtocolMapperWithConfig(Monitor):
    """Checks for the use of a specific Protocol Mapper, optionally with specific parameters

    Protocol Mappers allow incorporating information into the access token and performing other
    tasks. They are assigned to clients. In some situations, you may wish to monitor the use of
    specific mappers, e.g. those that accept input from HTTP header and write the result into
    specific fields of the access token.

    Protocol Mappers can be assigned to both clients and scopes. However, mappers assigned to a
    scope that isn't used by any client aren't interesting. So, whenever a scope is identified
    that uses a matching protocol mapper, it is only reported if it is used by a client that
    is not in the allowlist.
    """

    DEFAULT_SEVERITY = Severity.Medium
    SHORT_DESCRIPTION = "Unexpected use of Protocol Mapper detected"
    LONG_DESCRIPTION = "In the configuration, you have defined a specific type of Protocol Mapper to be sensitive. An unexpected use of this protocol mapper has been detected. If this is expected, please add it to the allowlist in the configuration file."
    REFERENCE = ""
    HAS_CUSTOM_CONFIG = True
    CUSTOM_CONFIG_TEMPLATE = {
        "protocol-mapper-type": "mapper name or regular expression",
        "matched-config": {
            "config-key (no regular expression)": "Matched config value (string or regular expression)",
            "hint": "you can also leave this dictionary empty to match all mappers of the defined type",
        },
    }

    @staticmethod
    def _protocol_mapper_matches_config(
        mapper: ProtocolMapper, target_mapper_type: str, target_mapper_config: dict[str, str]
    ) -> bool:
        # If the mapper type does not match, the whole thing isn't a match
        if not helper.matches_as_string_or_regex(mapper.get_protocol_mapper(), target_mapper_type):
            return False

        # Next, we need to check if the provided configuration matches.
        mapper_config = mapper.get_config()
        for cfg_key, cfg_value in target_mapper_config.items():
            # If the target config key is not defined for the mapper, it does not match
            if cfg_key not in mapper_config:
                return False
            # If it is defined, the actual value must match the provided value from the config.
            if not helper.matches_as_string_or_regex(mapper_config[cfg_key], cfg_value):
                return False
        # If we haven't returned False so far, all checks were successful and we can return True
        return True

    def _generate_additional_details(
        self, client: Client, mapper: ProtocolMapper, matched_by: str, matched_scope: str | None = None
    ) -> dict:
        additional_details: dict[str, Any] = {
            "matched_by": matched_by,
            "mapper": str(mapper),
            "mapper_config": mapper.get_config(),
            "client_default_scopes": client.get_default_client_scopes(),
            "client_optional_scopes": client.get_optional_client_scopes(),
            "client_has_service_account": client.has_service_account_enabled() and not client.is_public(),
        }
        if matched_scope is not None:
            additional_details["matched_scope"] = matched_scope
        if additional_details["client_has_service_account"]:
            saccount = self._DB.get_service_account(client.get_service_account_name())  # type: ignore
            additional_details["client_service_account_realm_roles"] = saccount.get_realm_roles()
            additional_details["client_service_account_client_roles"] = saccount.get_client_roles()
            additional_details["client_service_account_resolved_composite_roles"] = (
                helper.get_effective_roles_for_service_account(self._DB, saccount)
            )
        return additional_details

    def _should_consider_client(self, client: Client) -> bool:
        # Ignore clients that are disabled if the global setting says so
        return not self.is_ignored_disabled_client(client)

    def audit(self):
        custom_config = self.get_custom_config()
        for monitor_definition in custom_config:
            # Load config
            monitored_mapper_type: str = monitor_definition["protocol-mapper-type"]
            matched_config: dict[str, str] = monitor_definition["matched-config"]
            allowed_clients: list[str] = monitor_definition["allowed"]

            # Skip default config entry, in case it was still present
            if monitored_mapper_type == self.CUSTOM_CONFIG_TEMPLATE["protocol-mapper-type"]:  # type: ignore - Confused linter
                continue

            for client in self._DB.get_all_clients():
                if helper.matches_list_of_regexes(client.get_name(), allowed_clients):
                    continue
                if not self._should_consider_client(client):
                    continue
                # First, find all directly defined ProtocolMappers
                for mapper in client.get_protocol_mappers():
                    if self._protocol_mapper_matches_config(mapper, monitored_mapper_type, matched_config):
                        yield self.generate_finding_with_severity_from_config(
                            client,
                            monitor_definition,
                            additional_details=self._generate_additional_details(
                                client, mapper, "client_defined_mapper"
                            ),
                        )

                # Now, search all default and optional scopes
                for scope_name in client.get_default_client_scopes():
                    for mapper in self._DB.get_scope(scope_name).get_protocol_mappers():
                        if self._protocol_mapper_matches_config(mapper, monitored_mapper_type, matched_config):
                            yield self.generate_finding_with_severity_from_config(
                                client,
                                monitor_definition,
                                additional_details=self._generate_additional_details(
                                    client, mapper, "default_scope_defined_mapper", scope_name
                                ),
                            )
                for scope_name in client.get_optional_client_scopes():
                    for mapper in self._DB.get_scope(scope_name).get_protocol_mappers():
                        if self._protocol_mapper_matches_config(mapper, monitored_mapper_type, matched_config):
                            yield self.generate_finding_with_severity_from_config(
                                client,
                                monitor_definition,
                                additional_details=self._generate_additional_details(
                                    client, mapper, "optional_scope_defined_mapper", scope_name
                                ),
                            )
