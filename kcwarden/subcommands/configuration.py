import argparse
from io import TextIOBase

import yaml

from kcwarden.configuration.auditors import collect_auditors
from kcwarden.configuration.template import generate_config_template


def output_config(config: dict, file) -> None:
    # Create a custom yaml SafeDumper that deactivates aliases, as this makes the
    # resulting config file less readable.
    class NoAliasDumper(yaml.SafeDumper):
        def ignore_aliases(self, data):
            return True

    yaml.dump(config, Dumper=NoAliasDumper, sort_keys=False, stream=file)


def generate_config(args: argparse.Namespace):
    output_file: TextIOBase = args.output

    auditors = collect_auditors(additional_auditors_dirs=args.plugin_dir)

    output_config(config=generate_config_template(auditors), file=output_file)
