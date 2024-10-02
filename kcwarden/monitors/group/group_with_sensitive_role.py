from kcwarden.api import Monitor
from kcwarden.custom_types.result import Severity
from kcwarden.database import helper


class GroupWithSensitiveRole(Monitor):
    """Checks for the use of sensitive roles with specific groups.

    In some situations, specific roles should only be available for specific groups.
    This Auditor checks which groups have a specific role assigned to them. This includes
    roles inherited from their parent groups. Groups that are not explicitly permitted
    are reported.
    """

    DEFAULT_SEVERITY = Severity.Medium
    SHORT_DESCRIPTION = "Unexpected group has sensitive role assigned"
    LONG_DESCRIPTION = "In the configuration, you have defined this role to be sensitive, and defined a set of expected groups that are allowed to use it. An unexpected group has been detected that has been assigned this role as part of an optional or default scope. If this is expected, please add it to the allowlist in the configuration file."
    REFERENCE = ""
    HAS_CUSTOM_CONFIG = True
    CUSTOM_CONFIG_TEMPLATE = {
        "role": "Role name or regular expression",
        "role-client": "Client name (set to 'realm' for realm roles). No regular expression support",
        "allowed": ["/group-path", "/group/subgroup", "/group-name-(regex|support)"],
        # Overwrite the "allowed" key in the common template to show the correct format
    }

    def audit(self):
        custom_config = self.get_custom_config()
        for monitor_definition in custom_config:
            # Load config
            monitored_role: str = monitor_definition["role"]
            role_client: str = monitor_definition["role-client"]
            allowed_groups: list[str] = monitor_definition["allowed"]

            # Skip default config entry, in case it was still present
            if monitored_role == self.CUSTOM_CONFIG_TEMPLATE["role"]:  # type: ignore - confused linter
                continue

            for role in helper.retrieve_roles_from_db_with_regex(self._DB, role_client, monitored_role):
                # Find other roles that contain this role:
                for contained_role in helper.get_roles_containing_role(self._DB, role):
                    # Find groups that have this role assigned
                    for group in helper.get_groups_containing_role(self._DB, contained_role):
                        if not helper.matches_list_of_regexes(group.get_path(), allowed_groups) and self.is_not_ignored(
                            group
                        ):
                            yield self.generate_finding_with_severity_from_config(
                                group,
                                monitor_definition,
                                additional_details={
                                    "monitored_role": str(role),
                                    "matched_role": str(contained_role),
                                    "directly_assigned_realm_roles": group.get_realm_roles(),
                                    "directly_assigned_client_roles": group.get_client_roles(),
                                    "effective_realm_roles": group.get_effective_realm_roles(),
                                    "effective_client_roles": group.get_effective_client_roles(),
                                },
                            )
