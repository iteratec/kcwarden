from kcwarden.auditors.realm.abstract_realm_auditor import AbstractRealmAuditor
from kcwarden.custom_types.result import Severity
from kcwarden.utils.github import get_latest_keycloak_version


class KeycloakVersionShouldBeUpToDate(AbstractRealmAuditor):
    DEFAULT_SEVERITY = Severity.Medium
    SHORT_DESCRIPTION = "Keycloak version should be up-to-date"
    LONG_DESCRIPTION = "Only the latest version of Keycloak retrieves security fixes. The used version seems to be outdated and requires an update. Use a vulnerability scanner for a list of the actual vulnerabilities."
    REFERENCE = ""

    def audit_realm(self, realm):
        current_version = realm.get_keycloak_version()
        latest_version = get_latest_keycloak_version()
        # We use a rudimentary check here and do not perform a comparison based on semantic versioning, etc.
        is_outdated = current_version != latest_version
        # Special handling for the RedHat SSO or RedHat build of Keycloak
        is_redhat = "redhat" in current_version
        if is_outdated:
            yield self.generate_finding(
                realm,
                additional_details={
                    "current_version": current_version,
                    "latest_version": latest_version if latest_version is not None else "Could not be determined.",
                },
                # When the RedHat version is used, it is likely that this is a version with backports
                # and thus has hopefully less known security issues
                override_severity=Severity.Low if is_redhat else None,
                override_long_description=self.LONG_DESCRIPTION
                + " This might be false-positive since a RedHat version of "
                "Keycloak is used that might have received backports."
                if is_redhat
                else None,
            )
