from abc import ABC, abstractmethod
from typing import Generator

from kcwarden.custom_types import config_keys
from kcwarden.custom_types.database import Database
from kcwarden.custom_types.keycloak_object import Dataclass, Client
from kcwarden.custom_types.result import Severity, Result
from kcwarden.database import helper


class Auditor(ABC):
    DEFAULT_SEVERITY: Severity
    SHORT_DESCRIPTION: str
    LONG_DESCRIPTION: str
    REFERENCE: str
    HAS_CUSTOM_CONFIG: bool = False
    _DB: Database
    _CONFIG: dict[str, str | list | dict | bool]

    def __init__(self, db: Database, config: dict[str, str | list | dict | bool]):
        self._DB = db
        self._CONFIG = config

    @abstractmethod
    def audit(self) -> Generator[Result, None, None]:
        raise NotImplementedError()

    def generate_finding(
        self,
        dataclass_obj: Dataclass,
        additional_details: dict | None = None,
        override_short_description: str | None = None,
        override_long_description: str | None = None,
        override_reference: str | None = None,
        override_severity: Severity | None = None,
    ) -> Result:
        return Result(
            severity=override_severity if override_severity is not None else self.DEFAULT_SEVERITY,
            offending_object=dataclass_obj,
            short_description=self.SHORT_DESCRIPTION
            if override_short_description is None
            else override_short_description,
            long_description=self.LONG_DESCRIPTION if override_long_description is None else override_long_description,
            reference=self.REFERENCE if override_reference is None else override_reference,
            reporting_auditor=self.get_classname(),
            additional_details=additional_details or {},
        )

    ### Configuration Management
    # Generic config getter
    def get_config(self, key: str, default: str | bool | list | dict | None = None) -> str | list | dict | bool | None:
        return self._CONFIG.get(key, default)

    # Custom, Auditor-specific config
    @classmethod
    def has_custom_config(cls) -> bool:
        return cls.HAS_CUSTOM_CONFIG

    @classmethod
    def get_custom_config_template(cls) -> list[dict] | None:
        raise NotImplementedError(
            "Calling get_custom_config_template on an Auditor, which is only supported for Monitors."
        )

    def get_custom_config(self) -> list[dict]:
        custom_config_dict = self._CONFIG.get(config_keys.MONITOR_CONFIG, {})
        assert isinstance(custom_config_dict, dict)
        return custom_config_dict.get(self.get_classname(), [])

    ### Ignore List configuration
    # Specific ignore list from the config
    def _get_ignore_list(self) -> list[str]:
        ignore_dict = self._CONFIG[config_keys.AUDITOR_CONFIG]
        assert isinstance(ignore_dict, dict)
        return ignore_dict.get(self.get_classname(), [])

    # More generic ignores (also calls specific ignore list from config)
    def is_not_ignored(self, keycloak_object: Dataclass) -> bool:
        # Check if the provided object should be considered, based on the audit configuration.
        # If the object is in the explicit ignore list for the auditor, it should always be ignored.
        if helper.matches_list_of_regexes(keycloak_object.get_name(), self._get_ignore_list()):
            return False

        # Checks for clients:
        if isinstance(keycloak_object, Client):
            # If it is enabled, it should always be considered
            if keycloak_object.is_enabled():
                return True
            # Otherwise, it should be considered if "ignore disabled clients" is not set
            return not self.get_config(config_keys.IGNORE_DISABLED_CLIENTS)
        # Anything that doesn't have specific ignore rules associated with it is always considered.
        return True

    @classmethod
    def get_classname(cls) -> str:
        return cls.__name__

    def __str__(self) -> str:
        return self.get_classname()
