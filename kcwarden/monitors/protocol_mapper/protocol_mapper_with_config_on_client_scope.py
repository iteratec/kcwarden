from kcwarden.api import Monitor
from kcwarden.custom_types.keycloak_object import ProtocolMapper, ClientScope
from kcwarden.custom_types.result import Severity
from kcwarden.database import helper


class ProtocolMapperWithConfigOnClientScope(Monitor):
    """Checks for the use of a specific Protocol Mapper directly on a Client Scope

    Protocol Mappers allow incorporating information into the access token and performing other
    tasks. They can be assigned directly to client scopes. This monitor checks all client scopes
    for the use of specific protocol mappers, independently of which clients use those scopes.

    Use this monitor when you want to control which protocol mappers are configured on client
    scopes themselves, rather than monitoring the transitive effect on clients.
    """

    DEFAULT_SEVERITY = Severity.Medium
    SHORT_DESCRIPTION = "Unexpected use of Protocol Mapper on Client Scope detected"
    LONG_DESCRIPTION = "In the configuration, you have defined a specific type of Protocol Mapper to be sensitive. An unexpected use of this protocol mapper has been detected on a client scope. If this is expected, please add it to the allowlist in the configuration file."
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
        if not helper.matches_as_string_or_regex(mapper.get_protocol_mapper(), target_mapper_type):
            return False

        mapper_config = mapper.get_config()
        for cfg_key, cfg_value in target_mapper_config.items():
            if cfg_key not in mapper_config:
                return False
            if not helper.matches_as_string_or_regex(mapper_config[cfg_key], cfg_value):
                return False
        return True

    def _get_clients_using_scope(self, scope_name: str) -> list[str]:
        return [
            client.get_name()
            for client in self._DB.get_all_clients()
            if scope_name in client.get_default_client_scopes() or scope_name in client.get_optional_client_scopes()
        ]

    def _generate_additional_details(self, scope: ClientScope, mapper: ProtocolMapper) -> dict:
        clients_using_scope = self._get_clients_using_scope(scope.get_name())
        return {
            "mapper": str(mapper),
            "mapper_config": mapper.get_config(),
            "used_by_clients": clients_using_scope,
            "scope_is_used_by_any_client": len(clients_using_scope) > 0,
        }

    def audit(self):
        custom_config = self.get_custom_config()
        for monitor_definition in custom_config:
            monitored_mapper_type: str = monitor_definition["protocol-mapper-type"]
            matched_config: dict[str, str] = monitor_definition["matched-config"]
            allowed_scopes: list[str] = monitor_definition["allowed"]

            if monitored_mapper_type == self.CUSTOM_CONFIG_TEMPLATE["protocol-mapper-type"]:  # type: ignore - Confused linter
                continue

            for scope in self._DB.get_all_scopes():
                if helper.matches_list_of_regexes(scope.get_name(), allowed_scopes):
                    continue
                for mapper in scope.get_protocol_mappers():
                    if self._protocol_mapper_matches_config(mapper, monitored_mapper_type, matched_config):
                        yield self.generate_finding_with_severity_from_config(
                            scope,
                            monitor_definition,
                            additional_details=self._generate_additional_details(scope, mapper),
                        )
