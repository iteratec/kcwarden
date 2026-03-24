from kcwarden.api import Monitor
from kcwarden.custom_types.result import Severity
from kcwarden.database import helper


class RoleWithSensitiveAssociatedRole(Monitor):
    """Checks for composite roles that include a sensitive role.

    In Keycloak, roles can be composite — they implicitly grant all roles they include,
    potentially through multiple layers of nesting. This monitor checks whether any composite
    role unexpectedly contains a configured sensitive role (directly or transitively).

    You can define which composite roles are allowed to include the sensitive role in the
    config file. All other composite roles that contain it are reported.

    If no roles are defined in the config file, this monitor will not run.
    """

    DEFAULT_SEVERITY = Severity.Medium
    SHORT_DESCRIPTION = "Unexpected composite role includes sensitive role"
    LONG_DESCRIPTION = "In the configuration, you have defined this role to be sensitive, and defined a set of expected composite roles that are allowed to include it. An unexpected composite role has been detected that contains the sensitive role, directly or transitively. Anyone assigned that composite role will also receive the sensitive role. If this is expected, please add it to the allowlist in the configuration file."
    REFERENCE = ""
    HAS_CUSTOM_CONFIG = True
    CUSTOM_CONFIG_TEMPLATE = {
        "role": "Role name or regular expression",
        "role-client": "Client name (set to 'realm' for realm roles). No regular expression support",
    }

    def audit(self):
        custom_config = self.get_custom_config()
        for monitor_definition in custom_config:
            monitored_role: str = monitor_definition["role"]
            role_client: str = monitor_definition["role-client"]
            allowed_roles: list[str] = monitor_definition["allowed"]

            # Skip default config entry in case it was not replaced
            if monitored_role == self.CUSTOM_CONFIG_TEMPLATE["role"]:  # type: ignore - confused linter
                continue

            for role in helper.retrieve_roles_from_db_with_regex(self._DB, role_client, monitored_role):
                # get_roles_containing_role returns the role itself plus all composite roles
                # that contain it (directly or transitively). We skip the role itself.
                for container_role in helper.get_roles_containing_role(self._DB, role):
                    if container_role is role:
                        continue
                    if not helper.matches_list_of_regexes(
                        container_role.get_name(), allowed_roles
                    ) and self.is_not_ignored(container_role):
                        yield self.generate_finding_with_severity_from_config(
                            container_role,
                            monitor_definition,
                            additional_details={
                                "monitored_role": str(role),
                                "container_role": str(container_role),
                                "container_role_composites": container_role.get_composite_roles(),
                            },
                        )
