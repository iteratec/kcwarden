---
title: Introduction
---

# Security Guardrails

kcwarden can automatically detect many common misconfigurations using its Auditors feature.
However, because it doesn't have any knowledge about your specific context, it cannot detect misconfigurations specific to your setup, like incorrectly assigned roles or scopes.
In practice, these can be as bad as (or even worse than) more generic misconfigurations, because it can expose application permissions to unintended users.
Additionally, such errors can creep in during operation, meaning that checking for them once isn't enough.
Ideally, you want to continuously monitor for these problems and be notified as soon as they crop up.

## Introducing Monitors

To cover this use case, kcwarden contains a feature called _Monitors_, which allows you to configure custom checks using your knowledge of your specific setup.
For example, let's say that you have a role `org_admin`, which allows holders to configure organization-wide settings in your application.
Clearly, this shouldn't be assigned to just anyone.
Since all roles in your Keycloak setup are assigned to groups (instead of directly to users), let's create a monitor that checks which groups the role is assigned to, by adding the following to the configuration file:

```yaml
monitors:
- monitor: GroupWithSensitiveRole
  config:
  - role: "org_admin"
    severity: Critical
    role-client: realm   # it's a realm-wide role, not a client-specific role
    allowed:
      - /OrgAdm
    note: org_admin controls access to org management. Only the group /OrgAdm should have it.
```

Running kcwarden with this configuration file will flag any groups that have this role assigned and aren't in the allowlist.
You can then periodically run it on the current version of the realm configuration to ensure that there hasn't been any dangerous config drift.

!!! info

    We recommend testing monitors with an empty allowlist first to ensure that it returns results. Once you are satisfied that the detecting is working well, add your allowlist entries and test again.

kcwarden supports several different monitors.
Check the documentation of the individual monitors on the following pages to see what you can monitor with them.
Or contribute your own if your use case is not yet supported.

## Configuring Monitors

Generally, you can configure monitors as part of the kcwarden config file:
Generate a template using `kcwarden generate-config-template > config.yaml`, make your changes, and pass in the resulting file using `kcwarden audit -c config.yaml realm-dump.json`.
Monitors are configured under the top-level key `monitors` in the YAML configuration file.
Each monitor has its own entry in the config list, and you can put as much individual monitor configuration into the config list as you want:

```yaml
monitors:
- monitor: GroupWithSensitiveRole
  config:
  - role: "org_admin"
    severity: Critical
    role-client: realm
    allowed:
      - /OrgAdm
    note: org_admin controls access to org management. Only the group /OrgAdm should have it.
  - role: "site_admin"
    severity: Critical
    role-client: realm
    allowed:
      - /Staff
    note: site_admin controls access to overall admin functionality. Only the group /Staff should have it.
```

Part of the configuration options for each monitor are specific to that monitor, but two are generic: `severity` and `note`.

### Severity

The severity describes how serious a violation of the security guardrail would be.
You can set it to one of the following: `Info`, `Low`, `Medium`, `High`, `Critical`.
This can be used to prioritize your remediation work.
You can also filter the results using the `--min-severity` switch.

### Note

The note is a human-readable description of the semantics of the configuration.
It can contain arbitrary text, and will be returned as part of the output of the auditor when it has a finding.
Use it to remind yourself why you set up this rule, and what the consequences of violating it are.
