---
title: Role
---

# Role Monitor
You can use role monitors to detect if roles have unexpected configurations.
Please be sure that you have read our [general introduction to Monitors](index.md) to understand the context of this feature.

## RoleWithSensitiveAssociatedRole
This monitor allows you to check if a composite role unexpectedly includes a sensitive role, directly or transitively.
In Keycloak, composite roles implicitly grant all roles they contain — including through multiple levels of nesting.
This means that assigning a composite role to a user, group, or service account also silently grants every role it includes.
If a sensitive role ends up inside a composite role that should not have it, this creates an unintended privilege escalation that can be hard to spot.

For example, if you want to ensure that only the composite role `admin` is allowed to include the sensitive `org_admin` realm role, add the following to your configuration:

```yaml
monitors:
- monitor: RoleWithSensitiveAssociatedRole
  config:
  - role: "org_admin"
    severity: High
    role-client: realm
    allowed:
      - admin
    note: org_admin must only be composed into the admin role.
```

This monitor will detect both direct and transitive inclusions: if `outer-role` includes `intermediate-role` which in turn includes the monitored `org_admin`, both `intermediate-role` and `outer-role` will be reported.
The `role` and `allowed` fields support regular expressions, the `role-client` field does not.
Set the `role-client` field to `realm` when monitoring realm roles, or to the name of the client if it is a client role.

!!! info

    If you want to create comprehensive monitoring for a single role, we recommend combining this monitor with the [GroupWithSensitiveRole](group_monitor.md#groupwithsensitiverole), [ClientWithSensitiveRole](client_monitor.md#clientwithsensitiverole), and [ServiceAccountWithSensitiveRole](service_account_monitor.md#serviceaccountwithsensitiverole) monitors to achieve more comprehensive coverage.
