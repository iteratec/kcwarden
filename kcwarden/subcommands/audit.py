import argparse
import contextlib
import csv
import json
import sys
from typing import Type

import yaml

from kcwarden.configuration.auditors import collect_auditors
from kcwarden.configuration.template import generate_config_template
from kcwarden.custom_types import config_keys, result_headers
from kcwarden.api import Auditor
from kcwarden.custom_types.database import Database
from kcwarden.custom_types.result import Result, get_severity_by_name, Severity
from kcwarden.database.in_memory_db import InMemoryDatabase
from kcwarden.database.importer import load_realm_dump

DATABASE: Database = InMemoryDatabase()


def load_config_from_file(filename: str) -> dict[str, dict]:
    with open(filename, "r") as cfg_file:
        return yaml.safe_load(cfg_file)


def generate_config(args: argparse.Namespace, auditors: list[Type[Auditor]]) -> dict[str, str | list | dict | bool]:
    def _convert_config_template(config: dict, template: dict):
        for auditor_config in template[config_keys.AUDITOR_CONFIG]:
            assert isinstance(auditor_config, dict)
            auditor_name = auditor_config["auditor"]
            allowlist = auditor_config["allowed"]
            config[config_keys.AUDITOR_CONFIG][auditor_name] = allowlist
        for monitor_config in template[config_keys.MONITOR_CONFIG]:
            assert isinstance(monitor_config, dict)
            monitor_name = monitor_config["monitor"]
            monitor_cfg = monitor_config["config"]
            config[config_keys.MONITOR_CONFIG][monitor_name] = monitor_cfg
        return config

    # We are first generating an empty dictionary and then updating with the config template
    # because otherwise, the type checking of python will throw a fit about the types not
    # matching.
    cfg_dict = {config_keys.AUDITOR_CONFIG: {}, config_keys.MONITOR_CONFIG: {}}
    # We now need to load the config template and convert it into an internal representation
    # which is easier to work with for the rest of the system.
    cfg_template = generate_config_template(auditors)
    cfg_dict = _convert_config_template(cfg_dict, cfg_template)
    # Load data from the config file, if provided
    if args.config:
        cfg_file = load_config_from_file(args.config)
        # TODO At the moment, this will just blindly overwrite the values in the template.
        # In particular, it will not emit a warning if no Auditor of the specified name exists.
        # This is because the list of auditors in this part of the code may be smaller than
        # the list of auditors that actually exist, since we may only be using some auditors
        # (based on filtering using the --auditors parameter).
        # Emitting warnings if we have a more general config file while filtering down to specific
        # auditors would be unexpected and undesired, so I am leaving it like this for the moment
        # and will come back to it when I have more time.
        cfg_dict = _convert_config_template(cfg_dict, cfg_file)
    # Update remaining configuration from the CLI parameters
    cfg_dict[config_keys.IGNORE_DISABLED_CLIENTS] = args.ignore_disabled_clients
    return cfg_dict


def execute_auditors(auditors: list[Type[Auditor]], config: dict[str, str | list | dict | bool]) -> list[Result]:
    # Execute Auditor Modules
    findings = []
    for auditor in auditors:
        findings += [result for result in auditor(DATABASE, config).audit()]
    return findings


def output_findings(findings: list[Result], arguments: argparse.Namespace) -> None:
    # Long-term, this should support filtering by severity, etc.
    if arguments.min_severity is not None:
        min_sev = get_severity_by_name(arguments.min_severity)
    else:
        min_sev = Severity.Info

    output_file = arguments.output

    filtered_findings = [finding for finding in findings if finding.severity >= min_sev]

    output_format = arguments.format

    # If output_file is None, we want to fall back to stdout.
    # stdout should not be closed thus we use `nullcontext`.
    with open(output_file, "w") if output_file else contextlib.nullcontext(sys.stdout) as fo:
        if output_format == "json":
            json.dump([finding.to_dict() for finding in filtered_findings], fo, indent=4)
        elif output_format == "csv":
            writer = csv.DictWriter(fo, fieldnames=result_headers.ALL_HEADERS, dialect="excel")
            writer.writeheader()
            for finding in filtered_findings:
                writer.writerow(finding.to_dict())
        else:
            for finding in filtered_findings:
                fo.write(str(finding) + "\n")
                fo.write("\n---\n")


def audit(args: argparse.Namespace):
    # Split auditors, if available
    selected_auditors: list[str] | None = args.auditors
    # Collect all configured Auditors
    auditors = collect_auditors(selected_auditors, args.plugin_dir)
    # Generate config
    config = generate_config(args, auditors)
    # Load JSON data into database
    load_realm_dump(args.input_file, DATABASE)
    # Execute all auditor modules
    findings = execute_auditors(auditors, config)
    # Output the results
    output_findings(findings, args)
