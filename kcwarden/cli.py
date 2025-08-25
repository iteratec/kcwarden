import argparse
import logging
import os
import sys
from importlib.metadata import version

from kcwarden.custom_types.result import Severity
from kcwarden.subcommands import download, audit, configuration, review
from kcwarden.utils.arguments import is_dir, is_a_file

logger = logging.getLogger(__name__)

LOG_FORMAT = "[%(asctime)s %(levelname)-s %(name)s] %(message)s"


def add_plugin_directory_argument(parser: argparse.ArgumentParser):
    parser.add_argument(
        "--plugin-dir",
        "-p",
        help="The path to a directory with additional auditors.",
        required=False,
        nargs="*",
        type=is_dir,
    )


def add_config_dump_input_file_argument(parser: argparse.ArgumentParser):
    parser.add_argument(
        "input_file",
        help="Specify the file that contains the Keycloak config dump",
        type=argparse.FileType("r", encoding="UTF-8"),
    )


def get_parsers() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="kcwarden",
        description="Keycloak configuration auditor",
    )

    parser.add_argument("--version", action="version", version=f"%(prog)s {version('kcwarden')}")

    subparsers = parser.add_subparsers(required=True)

    #
    # The different subcommands:
    # The first positional argument determines which operation should be executed.
    # This allows a single entrypoint, e.g., for the Docker image.
    #

    # The actual audit execution
    add_audit_parser(subparsers)

    # Outputting default config
    add_config_generator_parser(subparsers)

    # Downloading the Keycloak configuration
    add_download_parser(subparsers)

    # Prepare data for human review
    add_review_parser(subparsers)

    return parser


def add_audit_parser(subparsers):
    parser_audit = subparsers.add_parser("audit", aliases=["a"], help="Audit a Keycloak configuration")
    parser_audit.set_defaults(func=audit.audit)
    add_config_dump_input_file_argument(parser_audit)
    parser_audit.add_argument(
        "-c",
        "--config",
        help="Provide a config file with auditor-specific exclusions and parameters. "
        "Generate a template using generate-config-template",
        type=is_a_file,
    )
    parser_audit.add_argument(
        "--format",
        "-f",
        help="The format of the output",
        choices=["txt", "csv", "json"],
        default="txt",
    )
    parser_audit.add_argument(
        "-o",
        "--output",
        help="File to which the results should be written. Defaults to stdout",
        type=argparse.FileType("w", encoding="UTF-8"),
        default="-",
    )
    parser_audit.add_argument(
        "-s",
        "--min-severity",
        help="The minimum severity of findings that should be reported.",
        choices=[s.name.upper() for s in Severity],
    )
    add_plugin_directory_argument(parser_audit)
    parser_audit.add_argument(
        "--auditors",
        help="Specify the exact auditors to run, separated by space (others will be ignored)",
        type=str,
        nargs="*",
    )
    parser_audit.add_argument(
        "--ignore-disabled-clients",
        help="When set, will not audit disabled OIDC clients",
        action="store_true",
    )

    parser_audit.add_argument(
        "--fail-on-findings",
        help="When set, will exit with return code 42 on findings. Otherwise, will exit with return code 0.",
        action="store_true",
    )


def add_config_generator_parser(subparsers):
    parser_config_generator = subparsers.add_parser(
        "generate-config-template", aliases=["gct"], help="Generate a config file template"
    )
    parser_config_generator.set_defaults(func=configuration.generate_config)
    add_plugin_directory_argument(parser_config_generator)
    parser_config_generator.add_argument(
        "-o",
        "--output",
        help="File to which the config should be written. Defaults to stdout",
        type=argparse.FileType("w", encoding="UTF-8"),
        default="-",
    )


def add_download_parser(subparsers):
    parser_download = subparsers.add_parser(
        "download",
        aliases=["d"],
        help="Download the Keycloak realm configuration.",
    )
    parser_download.set_defaults(func=download.download_config)
    parser_download.add_argument(
        "base_url", help="The base URL of the Keycloak install, including /auth if appropriate"
    )
    parser_download.add_argument(
        "-r",
        "--realm",
        help="The realm to download",
        required=True,
    )
    parser_download.add_argument(
        "-a",
        "--auth-realm",
        help="The realm used for authentication (default: master)",
        default="master",
        required=False,
    )

    # Authentication method choice
    parser_download.add_argument(
        "-m",
        "--auth-method",
        choices=["password", "client"],
        required=True,
        help="Choose the authentication method: password or client (client-credential grant / service account)",
    )

    # User authentication options
    parser_download.add_argument(
        "-u",
        "--user",
        help="The username used for user authentication. The password will be interactively prompted or read from the KCWARDEN_KEYCLOAK_PASSWORD env variable.",
    )
    parser_download.add_argument(
        "-t",
        "--totp",
        help="Indicates that a TOTP code is required for authentication. The value will be interactively prompted",
        action="store_true",
    )

    # Client credentials (can be used for both user and service account auth)
    parser_download.add_argument(
        "--client-id",
        default="admin-cli",
        help="The client ID for authentication. Defaults to admin-cli for password authentication.",
    )
    parser_download.add_argument(
        "--client-secret",
        help="The client secret for authentication, if required. Optional for password authentication, required for service account authentication. Can be omitted, in which case it will be read from the KCWARDEN_CLIENT_SECRET env variable.",
    )

    parser_download.add_argument(
        "-o",
        "--output",
        help="Specifies the file to which the export should be written. If not set, export will be written to STDOUT.",
        type=argparse.FileType("w", encoding="UTF-8"),
        default="-",
    )


def add_review_parser(subparsers):
    parser_review = subparsers.add_parser(
        "review", aliases=["r"], help="Prepare a matrix of Keycloak permissions for human review."
    )
    parser_review.set_defaults(func=review.prepare_review)
    add_config_dump_input_file_argument(parser_review)
    parser_review.add_argument(
        "-o",
        "--output",
        help="File to which the results should be written. Defaults to stdout. Will be in CSV format.",
        type=argparse.FileType("w", encoding="UTF-8"),
        default="-",
    )


def main(args: list[str] | None = None) -> int | None:
    logging.basicConfig(
        level=logging.DEBUG if os.environ.get("DEBUG", "false").lower() == "true" else logging.INFO, format=LOG_FORMAT
    )

    logger.debug("Started")

    # Parse CLI args
    args_ns = get_parsers().parse_args(args)
    # Execute the subcommand
    return args_ns.func(args_ns)


if __name__ == "__main__":
    sys.exit(main())
