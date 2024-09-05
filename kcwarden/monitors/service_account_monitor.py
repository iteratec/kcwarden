from kcwarden.custom_types.result import Severity
from kcwarden.api import Monitor
from kcwarden.database import helper


class ServiceAccountWithSensitiveRole(Monitor):
    """Checks for the use of sensitive roles with Service Accounts.

    In some situations, specific roles should only be available for specific users.
    This Auditor checks which Service Accounts have a specific role assigned to them,
    also considering composite groups. You can define which service accounts you would
    expect to have access to this role in the config file. All other service accounts
    with that role are reported.

    If no roles are defined in the config file, this auditor will not run.
    """

    DEFAULT_SEVERITY = Severity.Medium
    SHORT_DESCRIPTION = "Unexpected service account uses monitored sensitive role"
    LONG_DESCRIPTION = "In the configuration, you have defined this role to be sensitive, and defined a set of expected service accounts that are allowed to use it. An unexpected service account has been detected that has been assigned this role as part of an optional or default scope. If this is expected, please add it to the allowlist in the configuration file."
    REFERENCE = ""
    HAS_CUSTOM_CONFIG = True
    CUSTOM_CONFIG_TEMPLATE = {
        "role": "role name or regular expression",
        "role-client": "Client name (set to 'realm' for realm roles). No regular expression support",
    }

    def audit(self):
        custom_config = self.get_custom_config()
        for monitor_definition in custom_config:
            # Load config
            monitored_role: str = monitor_definition["role"]
            role_client: str = monitor_definition["role-client"]
            allowed_service_accounts: list[str] = monitor_definition["allowed"]

            # Skip default config entry, in case it was still present
            if monitored_role == self.CUSTOM_CONFIG_TEMPLATE["role"]:  # type: ignore - confused linter
                continue

            for role in helper.retrieve_roles_from_db_with_regex(self._DB, role_client, monitored_role):
                # Generate the final list of relevant roles. This includes all composite roles
                # that contain the relevant role.
                final_roles = helper.get_roles_containing_role(self._DB, role)

                # Get all groups that contain at least one of these roles
                groups = set([])
                for considered_role in final_roles:
                    groups.update(helper.get_groups_containing_role(self._DB, considered_role))

                # Next, we need to find all service accounts that have at least one of these roles
                for considered_role in final_roles:
                    for serviceaccount in helper.get_service_accounts_with_role(self._DB, considered_role):
                        if not helper.matches_list_of_regexes(serviceaccount.get_name(), allowed_service_accounts):
                            yield self.generate_finding_with_severity_from_config(
                                serviceaccount,
                                monitor_definition,
                                additional_details={
                                    "monitored_role": str(role),
                                    "matched_role": str(considered_role),
                                    "matched_by": "role",
                                    "service_account_realm_roles": serviceaccount.get_realm_roles(),
                                    "service_account_client_roles": serviceaccount.get_client_roles(),
                                },
                            )

                # And all service accounts that are in at least one of these groups
                for considered_group in groups:
                    for serviceaccount in helper.get_service_accounts_in_group(self._DB, considered_group):
                        if not helper.matches_list_of_regexes(serviceaccount.get_name(), allowed_service_accounts):
                            yield self.generate_finding_with_severity_from_config(
                                serviceaccount,
                                monitor_definition,
                                additional_details={
                                    "monitored_role": str(role),
                                    "matched_by": "group",
                                    "service_account_groups": serviceaccount.get_groups(),
                                },
                            )


class ServiceAccountWithGroup(Monitor):
    """Checks for service accounts assigned to specific groups.

    You may have a situation where you expect all service accounts to be assigned
    to specific groups (e.g., "/TecUser"), or no service accounts to be
    assigned to a group (e.g., "no service accounts should be assigned to /Customer").
    This monitor allows you to check for any violations of these rules.

    If no groups are defined in the config file, this auditor will not run.
    """

    DEFAULT_SEVERITY = Severity.Medium
    SHORT_DESCRIPTION = "Service Account in unexpected group"
    LONG_DESCRIPTION = "In the configuration, you have defined rules for which groups service accounts are allowed to be assigned to. This service account violates these rules. If this is a mistake, add an exclusion in the configuration."
    REFERENCE = ""
    HAS_CUSTOM_CONFIG = True
    CUSTOM_CONFIG_TEMPLATE = {"group": "/group path or regular expression", "allow_no_group": True}

    def audit(self):
        custom_config = self.get_custom_config()
        for monitor_definition in custom_config:
            # Load config
            monitored_group: str = monitor_definition["group"]
            allowed_service_accounts: list[str] = monitor_definition["allowed"]
            allow_no_group: bool = monitor_definition["allow_no_group"]

            # Skip default config entry, in case it was still present
            if monitored_group == self.CUSTOM_CONFIG_TEMPLATE["group"]:  # type: ignore - confused linter
                continue

            for saccount in self._DB.get_all_service_accounts():
                assigned_groups = saccount.get_groups()

                if not allow_no_group and assigned_groups == []:
                    yield self.generate_finding_with_severity_from_config(
                        saccount,
                        monitor_definition,
                        additional_details={"monitored_group": monitored_group, "assigned_groups": assigned_groups},
                    )
                    continue

                if helper.regex_matches_list_entry(monitored_group, assigned_groups):
                    if not helper.matches_list_of_regexes(saccount.get_username(), allowed_service_accounts):
                        yield self.generate_finding_with_severity_from_config(
                            saccount,
                            monitor_definition,
                            additional_details={"monitored_group": monitored_group, "assigned_groups": assigned_groups},
                        )


AUDITORS = [ServiceAccountWithGroup, ServiceAccountWithSensitiveRole]
