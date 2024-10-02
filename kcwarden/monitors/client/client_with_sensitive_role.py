from kcwarden.api import Monitor
from kcwarden.custom_types.keycloak_object import ProtocolMapper, Client, ClientScope
from kcwarden.custom_types.result import Severity
from kcwarden.database import helper


class ClientWithSensitiveRole(Monitor):
    """Checks for the use of sensitive roles.

    In some situations, specific roles should only be available for specific clients.
    This Auditor checks which OIDC clients have a specific role in their default or
    optional scopes, also considering composite groups. You can define which clients
    you would expect to have access to this role in the config file. All other clients
    that have the role in one of their scopes are reported. In addition, all clients
    that have "full scopes allowed" and the "roles" scope in their settings will also be
    reported.

    If no roles are defined in the config file, this auditor will not run.
    """

    DEFAULT_SEVERITY = Severity.Medium
    SHORT_DESCRIPTION = "Unexpected client uses monitored sensitive role"
    LONG_DESCRIPTION = "In the configuration, you have defined this role to be sensitive, and defined a set of expected clients that are allowed to use it. An unexpected client has been detected that has been assigned this role as part of an optional or default scope. If this is expected, please add it to the allowlist in the configuration file."
    REFERENCE = ""
    HAS_CUSTOM_CONFIG = True
    CUSTOM_CONFIG_TEMPLATE = {
        "role": "Role name or regular expression",
        "role-client": "Client name (set to 'realm' for realm roles). No regular expression support",
        "ignore_full_scope_allowed": True,
    }

    def _protocol_mapper_is_role_mapper(self, mapper: ProtocolMapper) -> bool:
        return mapper.get_protocol_mapper() in ["oidc-usermodel-client-role-mapper", "oidc-usermodel-realm-role-mapper"]

    def _get_role_mappers_for_client(self, client: Client) -> list[ProtocolMapper]:
        matched_mappers = []
        for mapper in client.get_protocol_mappers():
            if self._protocol_mapper_is_role_mapper(mapper):
                matched_mappers.append(mapper)
        return matched_mappers

    def _get_role_mapping_default_scopes_for_client(self, client: Client) -> list[str]:
        scopes = []
        for scope in client.get_default_client_scopes():
            for mapper in self._DB.get_scope(scope).get_protocol_mappers():
                if self._protocol_mapper_is_role_mapper(mapper):
                    scopes.append(scope)
        return scopes

    def _get_role_mapping_optional_scopes_for_client(self, client: Client) -> list[str]:
        scopes = []
        for scope in client.get_optional_client_scopes():
            for mapper in self._DB.get_scope(scope).get_protocol_mappers():
                if self._protocol_mapper_is_role_mapper(mapper):
                    scopes.append(scope)
        return scopes

    def _client_has_some_way_of_mapping_roles(self, client: Client) -> bool:
        return (
            self._get_role_mappers_for_client(client) != []
            or self._get_role_mapping_default_scopes_for_client(client) != []
            or self._get_role_mapping_optional_scopes_for_client(client) != []
        )

    def audit(self):
        custom_config = self.get_custom_config()
        for monitor_definition in custom_config:
            # Load config
            monitored_role: str = monitor_definition["role"]
            role_client: str = monitor_definition["role-client"]
            allowed_clients: list[str] = monitor_definition["allowed"]
            ignore_full_scope: bool = monitor_definition["ignore_full_scope_allowed"]

            if monitored_role == self.CUSTOM_CONFIG_TEMPLATE["role"]:  # type: ignore - Confused linter
                continue

            for role in helper.retrieve_roles_from_db_with_regex(self._DB, role_client, monitored_role):
                # Generate the final list of relevant roles. This includes all composite roles
                # that contain the relevant role.
                final_roles = helper.get_roles_containing_role(self._DB, role)

                # First, we check if the role has been directly assigned to any client.
                for considered_role in final_roles:
                    for client in helper.get_clients_with_directly_assigned_role(self._DB, considered_role):
                        # Having the right role directly assigned is not enough, the client also needs to have
                        # a role mapper that writes these roles to a token => also check for that
                        if (
                            self.is_not_ignored(client)
                            and not helper.matches_list_of_regexes(client.get_name(), allowed_clients)
                            and self._client_has_some_way_of_mapping_roles(client)
                        ):
                            yield self.generate_finding_with_severity_from_config(
                                client,
                                monitor_definition,
                                additional_details={
                                    "monitored_role": str(role),
                                    "matched_by": "RoleAssignmentToClient",
                                    "client_roles": client.get_directly_assigned_client_roles(),
                                    "realm_roles": client.get_directly_assigned_realm_roles(),
                                },
                            )

                # Next, we need to find all scopes that contain the relevant roles.
                scopes: list[ClientScope] = []
                for considered_role in final_roles:
                    scopes += helper.get_scopes_containing_role(self._DB, considered_role)

                # Finally, we need to find all clients that contain the relevant scopes
                for scope in scopes:
                    for client in helper.get_clients_with_scope(self._DB, scope):
                        # Having the right scope assigned is not enough, the client also needs to have
                        # a role mapper that writes these roles to a token => also check for that
                        if (
                            self.is_not_ignored(client)
                            and not helper.matches_list_of_regexes(client.get_name(), allowed_clients)
                            and self._client_has_some_way_of_mapping_roles(client)
                        ):
                            yield self.generate_finding_with_severity_from_config(
                                client,
                                monitor_definition,
                                additional_details={
                                    "monitored_role": str(role),
                                    "matched_by": "clientScope",
                                    "matched_scope": scope.get_name(),
                                    "default_scopes": client.get_default_client_scopes(),
                                    "optional_scopes": client.get_optional_client_scopes(),
                                },
                            )

                if ignore_full_scope:
                    continue

                # Finally, regardless of any specifics from scopes, clients that have "full scope allowed"
                # and a scope that contains mappers for client/realm roles (normally the "roles" scope, but
                # may also be a different one) will also always map all roles, including sensitive ones.
                # Relevant mapper types are oidc-usermodel-client-role-mapper and oidc-usermodel-realm-role-mapper.
                # In this case, we do not use _client_has_some_way_of_mapping_roles, as we want to be able to
                # trace where exactly the method for mapping roles is coming from, so we can report it.
                for client in self._DB.get_all_clients():
                    if (
                        self.is_not_ignored(client)
                        and not helper.matches_list_of_regexes(client.get_name(), allowed_clients)
                        and client.is_oidc_client()
                        and client.has_full_scope_allowed()
                    ):
                        # Check directly assigned protocol mappers for role mappers
                        for mapper in self._get_role_mappers_for_client(client):
                            yield self.generate_finding_with_severity_from_config(
                                client,
                                monitor_definition,
                                additional_details={
                                    "monitored_role": str(role),
                                    "matched_by": "full_scope_allowed_and_directly_assigned_role_mapper",
                                    "matched_role_mapper_name": mapper.get_name(),
                                    "matched_role_mapper_type": mapper.get_protocol_mapper(),
                                },
                            )

                        # Check default scopes
                        for scope in self._get_role_mapping_default_scopes_for_client(client):
                            yield self.generate_finding_with_severity_from_config(
                                client,
                                monitor_definition,
                                additional_details={
                                    "monitored_role": str(role),
                                    "matched_by": "full_scope_allowed_and_default_scope_with_role_mapper",
                                    "matched_scope": scope,
                                },
                            )
                        # Same for optional scopes
                        for scope in self._get_role_mapping_optional_scopes_for_client(client):
                            yield self.generate_finding_with_severity_from_config(
                                client,
                                monitor_definition,
                                additional_details={
                                    "monitored_role": str(role),
                                    "matched_by": "full_scope_allowed_and_optional_scope_with_role_mapper",
                                    "matched_scope": scope,
                                },
                            )
