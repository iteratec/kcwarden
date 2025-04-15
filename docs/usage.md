---
title: Usage
---

# Usage

!!! info

    You can use `-` as value for input and outputs to pass the input via `stdin` respective get the output via `stdout`.
    This is especially useful when using the container image so you don't need volume mounts.

## Getting a Config Dump

You need a realm export as input to the latter commands.
It can be acquired using the Keycloak administration interface or using the `download` command:

```shell
kcwarden download --realm $REALM --auth-method password --user $USER --output $KEYCLOAK_CONFIG_FILE $KEYCLOAK_BASE_URL
```

Additionally, you might specify a separate realm for login, e.g., the `master` realm, using the `--auth-realm` parameter.
The password will be promoted interactively, or loaded from the environment variable `$KCWARDEN_KEYCLOAK_PASSWORD` if set.



If you want to run `kcwarden` as part of a pipeline, we recommend using service account authentication instead. Create a confidential client with a service account, and assign the `manage-realm`, `manage-clients` and `manage-users` roles for the relevant realm to it. Then, use kcwarden like this:

```bash
kcwarden download --auth-method client --client-id kcwarden-client --client-secret $YOUR_CLIENT_SECRET
# (add additional parameters as needed)
```

You can also omit the `--client-secret` parameter, in which case it will be loaded from the `$KCWARDEN_CLIENT_SECRET` environment variable.

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
| `--min-severity`            | The minimum severity of findings that should be reported. Can be one of INFO, LOW, MEDIUM, HIGH, CRITICAL.                                              |
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

There is an additional command `review` that outputs roles and its usages on services accounts and groups as matrix for human analysis.

```shell
kcwarden review $KEYCLOAK_CONFIG_FILE
```
