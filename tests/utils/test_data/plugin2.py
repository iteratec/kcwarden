from collections.abc import Generator

from kcwarden.api import Auditor, Monitor
from kcwarden.custom_types.result import Result


class Plugin3(Auditor):
    def audit(self) -> Generator[Result, None, None]:
        pass

    @classmethod
    def get_custom_config_template(cls) -> list[dict] | None:
        return None


class Plugin4(Monitor):
    CUSTOM_CONFIG_TEMPLATE = {"a": "b"}

    def audit(self) -> Generator[Result, None, None]:
        pass