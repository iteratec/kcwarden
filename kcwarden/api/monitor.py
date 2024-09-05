from abc import ABC

from .auditor import Auditor
from kcwarden.custom_types.keycloak_object import Dataclass
from kcwarden.custom_types.result import Severity, Result, get_severity_by_name


class Monitor(Auditor, ABC):
    HAS_CUSTOM_CONFIG: bool = True
    COMMON_CUSTOM_CONFIG_TEMPLATE: dict = {
        "allowed": ["allowed-entity-name", "allowed-entity-regex.*"],
        "note": "A note on why a match is interesting. Will be part of the output on matches.",
        "severity": "Placeholder, will be replaced in get_custom_config_template",
    }

    # The CUSTOM_CONFIG_TEMPLATE defines additional fields for the configuration that should be merged into the common
    # custom config format.
    CUSTOM_CONFIG_TEMPLATE: dict | None = None

    @classmethod
    def get_custom_config_template(cls) -> list[dict] | None:
        if cls.CUSTOM_CONFIG_TEMPLATE is None:
            raise NotImplementedError(
                "Monitor %s does not set CUSTOM_CONFIG_TEMPLATE. Must be set." % cls.get_classname()
            )

        config = cls.COMMON_CUSTOM_CONFIG_TEMPLATE | cls.CUSTOM_CONFIG_TEMPLATE
        # Set default severity override
        config["severity"] = cls.DEFAULT_SEVERITY.name
        return [config]

    def generate_finding_with_severity_from_config(
        self,
        dataclass_obj: Dataclass,
        matched_config: dict,
        additional_details: dict | None = None,
        override_short_description: str | None = None,
        override_long_description: str | None = None,
        override_reference: str | None = None,
        override_severity: Severity | None = None,
    ) -> Result:
        """
        Generate a finding that considers the severity from the matched config.
        """
        severity = override_severity
        if severity is None:
            severity = get_severity_by_name(matched_config.get("severity")) if "severity" in matched_config else None

        return self.generate_finding(
            dataclass_obj,
            additional_details,
            override_short_description,
            override_long_description,
            override_reference,
            severity,
        )
