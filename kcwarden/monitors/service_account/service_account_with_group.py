from kcwarden.api import Monitor
from kcwarden.custom_types.result import Severity
from kcwarden.custom_types.keycloak_object import ServiceAccount, Client
from kcwarden.database import helper


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

    def _should_consider_service_account(
        self, service_account: ServiceAccount, allowed_service_accounts: list[str]
    ) -> bool:
        if not helper.matches_list_of_regexes(service_account.get_username(), allowed_service_accounts):
            client: Client = self._DB.get_client(service_account.get_client_id())
            return not self.is_ignored_disabled_client(client)
        return False

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
                if not self._should_consider_service_account(saccount, allowed_service_accounts):
                    continue
                assigned_groups = saccount.get_groups()

                if not allow_no_group and assigned_groups == []:
                    yield self.generate_finding_with_severity_from_config(
                        saccount,
                        monitor_definition,
                        additional_details={"monitored_group": monitored_group, "assigned_groups": assigned_groups},
                    )
                    continue

                if helper.regex_matches_list_entry(monitored_group, assigned_groups):
                    yield self.generate_finding_with_severity_from_config(
                        saccount,
                        monitor_definition,
                        additional_details={"monitored_group": monitored_group, "assigned_groups": assigned_groups},
                    )
