from typing import Type

from kcwarden.custom_types import config_keys
from kcwarden.api import Auditor


def generate_config_template(auditors: list[Type[Auditor]]) -> dict[str, list[dict]]:
    config = {config_keys.AUDITOR_CONFIG: [], config_keys.MONITOR_CONFIG: []}

    for auditor in auditors:
        if auditor.has_custom_config():
            config[config_keys.MONITOR_CONFIG].append(
                {"monitor": auditor.get_classname(), "config": auditor.get_custom_config_template()}
            )
        else:
            config[config_keys.AUDITOR_CONFIG].append({"auditor": auditor.get_classname(), "allowed": []})
    return config
