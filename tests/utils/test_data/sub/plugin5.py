import abc
from typing import Generator

from kcwarden.api import Auditor
from kcwarden.custom_types.result import Result


class NonPlugin:
    pass


def non_plugin():
    pass


class Plugin5(Auditor):
    def audit(self) -> Generator[Result, None, None]:
        pass

    @classmethod
    def get_custom_config_template(cls) -> list[dict] | None:
        return None


class AbstractPlugin(Auditor, abc.ABC):
    pass
