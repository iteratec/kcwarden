---
title: Advanced Usage
---

# Advanced Usage

## Using Custom Auditors {: #plugins}

You can add your own auditors to kcwarden without the need to bring them upstream 
or to handle a messy local copy of the kcwarden repository.

Using the commandline parameter `--plugin-dir` for the [`audit`](./usage.md#audit) and
the [`generate-config-template`](./usage.md#generate-config-template) subcommands,
you can specify paths to Python packages with your own auditors.
Multiple paths can be passed space-separated.
These packages must be regular Python packages with a `__init__.py` (also nested).
All classes from these packages that inherit from 
[`Auditor`](https://github.com/iteratec/kcwarden/blob/main/kcwarden/api/auditor.py) and 
that are not abstract are automatically collected.
In your custom auditors, you need to implement the `audit` method that yields findings.

## Continuously running kcwarden

Since the Keycloak configuration is mostly dynamic, you probably want to run kcwarden regularly
to get notified when it derivates from the guardrails you defined in your kcwarden configuration.
You can manually run it or using a scheduled job, e.g., leveraging a CI/CD pipeline.

### GitLab CI/CD Example

In GitLab CI/CD, your job could look like this:

```yaml
kcwarden:
  stage: audit
  image: ghcr.io/iteratec/kcwarden:latest

  variables:
    KCWARDEN_KEYCLOAK_PASSWORD: ${KEYCLOAK_ADMIN_PASSWORD}

  script:
    - echo "🚀 Running kcwarden"
    - >-
      kcwarden download -r "${KEYCLOAK_REALM}" -m password
      -u "${KEYCLOAK_ADMIN_USERNAME}"
      "${KEYCLOAK_URL}" -o "${KEYCLOAK_CONFIG_FILE}"
    - >-
      kcwarden audit --ignore-disabled-clients --fail-on-findings
      --config "./kcwarden-config.yaml" "${KEYCLOAK_CONFIG_FILE}"
```


