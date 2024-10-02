from typing import Generator

from kcwarden.api import Auditor
from kcwarden.custom_types.result import Result, Severity


class NonPlugin:
    pass


def non_plugin():
    pass


class Plugin1(Auditor):
    def audit(self) -> Generator[Result, None, None]:
        yield self.generate_finding(
            next(iter(self._DB.get_all_realms())), {}, "IMPORTANT", override_severity=Severity.Critical
        )

    @classmethod
    def get_custom_config_template(cls) -> list[dict] | None:
        return None


class Plugin2(Auditor):
    def audit(self) -> Generator[Result, None, None]:
        pass

    @classmethod
    def get_custom_config_template(cls) -> list[dict] | None:
        return None
