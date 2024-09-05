---
title: Usage
---

# Usage

## Getting a Config Dump

You need a realm export as input to the latter commands.
It can be acquired using the Keycloak administration interface or using the `download` command:

```shell
kcwarden download --realm $REALM --user $USER --output $KEYCLOAK_CONFIG_FILE $KEYCLOAK_BASE_URL
```

Additionally, you might specify a separate realm for login, e.g., the `master` realm, using the `--auth-realm`
parameter.

## Running the Audit

To execute the actual audit, you can use the `audit` command:

```shell
kcwarden audit $KEYCLOAK_CONFIG_FILE
```

There are several optional parameters to customize the execution:

| Parameter                   | Description                                                                                                                                             |
|-----------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------|
| `--format`                  | The output format of the findings. Can be plain text (`txt`), `csv` or `json`.                                                                          |
| `--output`                  | The path to the output file. If not provided, the output will be printed on stdout.                                                                     |
| `--min-severity`            | The minimum severity of findings that should be reported. Can be one of INFO, WARNING, ERROR, CRITICAL.                                                 |
| `--auditors`                | Specify the exact auditors to run, separated by space (others will be ignored).                                                                         |
| `--config`                  | Provide a config file with auditor-specific exclusions and parameters. Generate a template using [generate-config-template](#generate-config-template). |
| `--ignore-disabled-clients` | When set, will not audit disabled OIDC clients.                                                                                                         |

## Generating a _kcwarden_ Configuration {: #generate-config-template}

The [auditors](./auditors/index.md) and [monitors](./monitors/index.md) can be configured in a YAML configuration file.
The stub for this file can be generated using the `generate-config-template` command:

```shell
kcwarden generate-config-template --output $CONFIG_FILE
```

If `--output` is not specified, it is printed to stdout.

## Review Permissions

!!! info

    This feature is not part of the main scope of _kcwarden_ and thus only partly maintained.

There is an additional command `review` that outputs roles and its usages on services accounts and groups as matrix for
human analysis.

```shell
kcwarden review $KEYCLOAK_CONFIG_FILE
```
