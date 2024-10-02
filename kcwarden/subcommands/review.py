import argparse
import contextlib
import csv
import sys

from kcwarden.custom_types import config_keys
from kcwarden.custom_types.database import Database
from kcwarden.custom_types.keycloak_object import RealmRole, ClientRole
from kcwarden.database.in_memory_db import InMemoryDatabase
from kcwarden.database.importer import load_realm_dump
from kcwarden.monitors.service_account.service_account_with_sensitive_role import ServiceAccountWithSensitiveRole

DATABASE: Database = InMemoryDatabase()


def _configure_monitor_for_role(role: RealmRole | ClientRole) -> dict:
    return {
        config_keys.MONITOR_CONFIG: {
            ServiceAccountWithSensitiveRole.get_classname(): [
                {
                    "role": role.get_name(),
                    "role-client": role.get_client_name() if role.is_client_role() else "realm",  # type: ignore
                    "allowed": [],
                    "severity": "INFO",
                }
            ]
        }
    }


def _combine_role_identifier(role: RealmRole | ClientRole) -> str:
    prefix = role.get_client_name() if role.is_client_role() else "realm"  # type: ignore
    return prefix + "." + role.get_name()


def get_service_account_list() -> list[str]:
    return [sa.get_username() for sa in DATABASE.get_all_service_accounts()]


def map_service_account_to_roles(service_accounts: list[str]) -> list[dict]:
    # Prepare a list for the results
    results = []
    # Now, go through every realm role and see which service account has access to it
    for role in DATABASE.get_all_realm_roles():
        # Prepare a dict to hold the results for this role
        role_res = {x: "" for x in service_accounts}
        role_res["role"] = _combine_role_identifier(role)
        # Instantiate a config for the relevant monitor to find the realm roles
        monitor_cfg = _configure_monitor_for_role(role)
        mon = ServiceAccountWithSensitiveRole(DATABASE, monitor_cfg)
        for result in mon.audit():
            role_res[result._offending_object.get_name()] = result._additional_details["matched_by"]
        results.append(role_res)

    # Next, do the same thing for client roles
    client_roles = DATABASE.get_all_client_roles()
    for client in client_roles.keys():
        for role in client_roles[client].values():
            # Prepare a dict to hold the results for this role
            role_res = {x: "" for x in service_accounts}
            role_res["role"] = _combine_role_identifier(role)
            # Instantiate a config for the relevant monitor to find the realm roles
            monitor_cfg = _configure_monitor_for_role(role)
            mon = ServiceAccountWithSensitiveRole(DATABASE, monitor_cfg)
            for result in mon.audit():
                role_res[result._offending_object.get_name()] = result._additional_details["matched_by"]
            results.append(role_res)

    return results


def output_findings(findings: list[dict], service_accounts: list[str], output_file: str) -> None:
    field_names = ["role"]
    field_names += service_accounts
    # If output_file is None, we want to fall back to stdout.
    # stdout should not be closed thus we use `nullcontext`.
    with open(output_file, "w") if output_file else contextlib.nullcontext(sys.stdout) as fo:
        writer = csv.DictWriter(fo, fieldnames=field_names, dialect="excel")
        writer.writeheader()
        for finding in findings:
            writer.writerow(finding)


def prepare_review(args: argparse.Namespace):
    load_realm_dump(args.input_file, DATABASE)
    # Load list of service accounts
    service_accounts = get_service_account_list()
    # Find mapping of service accounts and roles
    findings = map_service_account_to_roles(service_accounts)
    # Output the results
    output_findings(findings, service_accounts, args.output)
