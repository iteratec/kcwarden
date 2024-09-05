from pathlib import Path
from typing import Type

from kcwarden.auditors import client_auditor, realm_auditor, idp_auditor, scope_auditor
from kcwarden.api import Auditor
from kcwarden.monitors import client_monitor, group_monitor, service_account_monitor, protocol_mapper_monitor
from kcwarden.utils import plugins


def collect_auditors(
    requested_auditors: list[str] | None = None, additional_auditors_dirs: list[Path] | None = None
) -> list[Type[Auditor]]:
    auditors = []
    # TODO Add new auditor modules here
    auditors.extend(client_auditor.AUDITORS)
    auditors.extend(realm_auditor.AUDITORS)
    auditors.extend(idp_auditor.AUDITORS)
    auditors.extend(scope_auditor.AUDITORS)
    auditors.extend(client_monitor.AUDITORS)
    auditors.extend(group_monitor.AUDITORS)
    auditors.extend(service_account_monitor.AUDITORS)
    auditors.extend(protocol_mapper_monitor.AUDITORS)

    if additional_auditors_dirs is not None:
        for directory in additional_auditors_dirs:
            auditors.extend(plugins.get_auditors(directory))

    if requested_auditors is not None:
        auditors = [auditor for auditor in auditors if auditor.get_classname() in requested_auditors]
    return auditors
