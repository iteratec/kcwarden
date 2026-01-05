from pathlib import Path
from typing import Type

from kcwarden.auditors import (
    realm as realm_auditors,
    client as client_auditors,
    idp as idp_auditors,
    scope as scope_auditors,
)
from kcwarden.api import Auditor
from kcwarden.monitors import (
    client as client_monitors,
    group as group_monitors,
    service_account as service_account_monitors,
    protocol_mapper as protocol_mapper_monitors,
)
from kcwarden.utils import auditor_importing


def collect_auditors(
    requested_auditors: list[str] | None = None, additional_auditors_dirs: list[Path] | None = None
) -> list[Type[Auditor]]:
    """
    Collect all relevant auditors for this run.
    This includes built-in auditors and monitors plus the ones provided in optional plugin directories.
    If not all auditors should be applied, the results are filtered for the requested ones.
    """
    auditors = []
    for package in (
        client_auditors,
        realm_auditors,
        idp_auditors,
        scope_auditors,
        client_monitors,
        group_monitors,
        service_account_monitors,
        protocol_mapper_monitors,
    ):
        auditors.extend(sorted(auditor_importing.get_auditors_from_package(package), key=lambda a: a.get_classname()))

    if additional_auditors_dirs is not None:
        for directory in additional_auditors_dirs:
            auditors.extend(
                sorted(auditor_importing.get_auditors_from_directory(directory), key=lambda a: a.get_classname())
            )

    if requested_auditors is not None:
        auditors = [auditor for auditor in auditors if auditor.get_classname() in requested_auditors]
    return auditors
